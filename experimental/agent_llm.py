"""AI 調查員怎麼呼叫 AI。和一般問答唯一的不同：AI 多了 agent_tools.py 的唯讀工具可以用。

- Claude Code、Codex：把 mcp_server.py 接上去（llm.py 的 _claude、_codex 的 server 參數），其他內建功能照樣全部關掉
- Gemini API：程式自己跑「AI 想查 → 程式用工具箱查 → 結果交回給 AI」的迴圈

這裡的函式只會被 investigate.py 透過 guard.ask_llm(..., send=...) 呼叫，所以資料一樣要先過海關。
這個檔案會用到 llm.py 裡底線開頭的內部函式。
"""
import importlib.util
import sys

import llm
from common import BASE
from experimental import agent_tools

MCP_SERVER = BASE / "experimental" / "mcp_server.py"
GEMINI_MAX_TURNS = 40


def ready():
    """AI 調查員需要的東西都在嗎？回傳 (可以用嗎, 不能用的原因)。"""
    if llm._backend in ("claude", "codex") and importlib.util.find_spec("mcp") is None:
        return False, "AI 調查員要先安裝 MCP 套件（pip install mcp）"
    return True, None


def investigate(system_prompt, prompt, data_dir, run_id):
    """AI 只能用 agent_tools.py 的工具。回傳 AI 最後的回答。"""
    return llm._with_fallback(lambda: _investigate(system_prompt, prompt, data_dir, run_id))


def _investigate(system_prompt, prompt, data_dir, run_id):
    if llm._backend == "gemini":
        return gemini_investigate(system_prompt, prompt, agent_tools.ToolBox(data_dir, run_id, "evidence.json"))
    server = [sys.executable, str(MCP_SERVER), "--data", str(data_dir), "--run", run_id, "--findings", "evidence.json"]
    if llm._backend == "claude":
        return llm._claude(system_prompt, prompt, server)
    return llm._codex(system_prompt, prompt, server)


def gemini_investigate(system_prompt, prompt, box):
    """程式自己跑「AI 想查 → 程式用工具箱查 → 結果交回給 AI」的迴圈。AI 沒有工具箱以外的任何功能。"""
    base = {"systemInstruction": {"parts": [{"text": system_prompt}]},
            "tools": [{"functionDeclarations": agent_tools.declarations()}]}
    contents = [{"role": "user", "parts": [{"text": prompt}]}]
    for _ in range(GEMINI_MAX_TURNS):
        content = llm._gemini_generate({**base, "contents": contents})
        calls = [part["functionCall"] for part in content["parts"] if "functionCall" in part]
        if not calls:
            return llm._gemini_text(content)
        contents.append(content)  # 原封不動放回去：Gemini 3 需要裡面的 thoughtSignature
        responses = []
        for call in calls:
            response = {"name": call.get("name"), "response": box.call(call.get("name"), call.get("args"))}
            if call.get("id"):
                response["id"] = call["id"]
            responses.append({"functionResponse": response})
        contents.append({"role": "user", "parts": responses})
    raise RuntimeError("AI 調查的回合太多，已停止")
