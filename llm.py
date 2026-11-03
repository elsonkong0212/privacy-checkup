"""AI 後端。

auto  ：預設值。依序找 Claude Code CLI、Codex CLI、Gemini API 金鑰，用第一個找到的；都沒有就不用 AI
        CLI 要裝了而且登入了才算數；第一次呼叫就失敗（例如方案不含、額度用完）會自動換下一個
claude：Claude Code CLI（沿用你的 Claude 訂閱，不需要另外申請 API key）
codex ：OpenAI Codex CLI（沿用你的 ChatGPT 訂閱，先執行一次 codex login）
gemini：Google Gemini API（到 Google AI Studio 申請免費的 API 金鑰，由程式直接呼叫）
none  ：不使用 AI，所有判斷改用規則，報告照樣產生

不管用哪一種，AI 都只拿得到我們給它的東西：
- 一般問答（AI-1/2/3）：AI 沒有任何工具，只能回答文字
- 調查模式（--agent）：AI 只有 agent_tools.py 的唯讀工具；內建的讀檔、執行指令、上網功能全部關掉
- CLI 一律在空的暫存資料夾裡執行，就算有工具也碰不到專案裡的檔案
Codex 的內建功能很多，所以另外會檢查它的執行紀錄：只要用了我們的工具以外的功能，這次結果就作廢。
"""
import glob
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from common import BASE

NAMES = {"claude": "Claude Code CLI", "codex": "Codex CLI", "gemini": "Gemini API"}
CHOICES = ["auto", "claude", "codex", "gemini", "none"]
MCP_SERVER = BASE / "mcp_server.py"
TIMEOUT, AGENT_TIMEOUT = 300, 900

_backend = "none"
_auto = False
_binary = None
_model = None
_api_key = None
_codex_disabled = []
_candidates = []   # auto 模式：還沒試過、可以換過去的 AI（依優先順序）
_verified = False  # 目前的 AI 在這次執行裡成功回答過了嗎？成功過就固定用它，不再換


def detect():
    """--llm auto：這台電腦上有哪幾種 AI 可以用？依序是 Claude Code CLI、Codex CLI、Gemini API 金鑰。
    CLI 要裝了而且登入了才算；查不出有沒有登入（例如舊版沒有這個指令）就先算可以用，真的呼叫失敗再換下一個。"""
    found = []
    for backend, find, logged_in, hint in [
        ("claude", find_claude, _claude_logged_in, "在 VS Code 的 Claude Code 面板登入，或在終端機執行 claude 後輸入 /login"),
        ("codex", find_codex, _codex_logged_in, "在 VS Code 的 Codex 面板登入，或在終端機執行 codex login"),
    ]:
        binary = find()
        if not binary:
            continue
        if logged_in(binary) is False:
            print(f"[注意] 找到 {NAMES[backend]}，但還沒登入，先略過。要用的話請{hint}。")
            continue
        found.append(backend)
    if gemini_api_key():
        found.append("gemini")
    return found


def configure(backend, model=None):
    global _backend, _auto, _model, _candidates, _verified
    _auto, _model, _verified, _backend = backend == "auto", model, False, "none"
    _candidates = detect() if _auto else ([] if backend == "none" else [backend])
    _switch()


def _switch():
    """改用清單裡下一個準備得好的 AI，成功回傳 True。清單用完就回傳 False，目前用的 AI 不變。"""
    while _candidates:
        if _activate(_candidates.pop(0)):
            return True
    return False


def _activate(backend):
    """準備好指定的 AI，成功回傳 True；失敗時印出原因，目前用的 AI 不變。"""
    global _backend, _binary, _model, _api_key, _codex_disabled
    if backend == "claude":
        binary = find_claude()
        if not binary:
            return _unavailable("找不到 Claude Code CLI", "可以設定環境變數 CLAUDE_BIN 指向 claude 執行檔。")
        _binary = binary
    elif backend == "codex":
        binary = find_codex()
        if not binary:
            return _unavailable("找不到 Codex CLI", "安裝方式：npm install -g @openai/codex，再執行 codex login。")
        _binary = binary
        _codex_disabled = _codex_features_to_disable()
    elif backend == "gemini":
        key = gemini_api_key()
        if not key:
            return _unavailable("找不到 Gemini API 金鑰", "到 https://aistudio.google.com/apikey 免費申請，"
                                "存成 secrets/gemini_api_key.txt，或設定環境變數 GEMINI_API_KEY。")
        _api_key = key
        try:
            model = _model or _gemini_pick_model()
        except Exception as error:
            return _unavailable(f"連不上 Gemini API（{error}）", "請檢查網路和 API 金鑰。")
        _model = model
    else:
        return False
    _backend = backend
    return True


def _unavailable(problem, hint):
    print(f"[注意] {problem}，{'略過' if _auto else '改用離線模式（不使用 AI）'}。")
    print(f"       {hint}")
    return False


def available():
    return _backend != "none"


def agent_ready():
    """AI 調查員需要的東西都在嗎？回傳 (可以用嗎, 不能用的原因)。"""
    if _backend in ("claude", "codex") and importlib.util.find_spec("mcp") is None:
        return False, "AI 調查員要先安裝 MCP 套件（pip install mcp）"
    return True, None


def describe():
    if _backend == "none":
        return ("未使用（這台電腦找不到已登入的 Claude Code、Codex，也沒有 Gemini 金鑰，全部用規則判斷）" if _auto
                else "未使用（離線模式，全部用規則判斷）")
    return (NAMES[_backend] + (f"（模型：{_model}）" if _model else "")
            + ("（自動偵測；要換可以加 --llm）" if _auto else ""))


def complete(system_prompt, prompt):
    """一般問答：AI 沒有任何工具。"""
    return _with_fallback(lambda: _complete(system_prompt, prompt))


def investigate(system_prompt, prompt, data_dir, run_id):
    """調查模式：AI 只能用 agent_tools.py 的工具。回傳 AI 最後的回答。"""
    return _with_fallback(lambda: _investigate(system_prompt, prompt, data_dir, run_id))


def _with_fallback(ask):
    """auto 模式下，目前的 AI 第一次呼叫就失敗（例如方案不含、額度用完），換下一個找得到的 AI 再問一次。
    成功過一次之後就固定用它：之後的失敗照常交給呼叫的人處理（改用規則判斷），不會中途換 AI。"""
    global _verified
    while True:
        try:
            reply = ask()
        except Exception as error:
            failed = NAMES.get(_backend, _backend)
            if not _auto or _verified or not _switch():
                raise
            print(f"  [注意] {failed} 呼叫失敗（{str(error)[:150]}），改用 {NAMES[_backend]} 再試一次")
            continue
        _verified = True
        return reply


def _complete(system_prompt, prompt):
    if _backend == "claude":
        return _claude(system_prompt, prompt)
    if _backend == "codex":
        return _codex(system_prompt, prompt)
    return _gemini_complete(system_prompt, prompt)


def _investigate(system_prompt, prompt, data_dir, run_id):
    if _backend == "gemini":
        import agent_tools  # 放在這裡，避免 guard → llm → agent_tools → guard 互相引用
        return _gemini_investigate(system_prompt, prompt, agent_tools.ToolBox(data_dir, run_id, "evidence.json"))
    server = [sys.executable, str(MCP_SERVER), "--data", str(data_dir), "--run", run_id, "--findings", "evidence.json"]
    if _backend == "claude":
        return _claude(system_prompt, prompt, server)
    return _codex(system_prompt, prompt, server)


def _run(command, stdin, cwd, timeout, env=None):
    return subprocess.run(command, input=stdin, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=cwd, env=env, timeout=timeout)


# ---------- Claude Code CLI ----------

def find_claude():
    if os.environ.get("CLAUDE_BIN"):
        return os.environ["CLAUDE_BIN"]
    found = shutil.which("claude")
    if found:
        return found
    # VS Code 的 Claude Code 擴充套件內附的執行檔
    name = "claude.exe" if os.name == "nt" else "claude"
    pattern = str(Path.home() / ".vscode" / "extensions" / "anthropic.claude-code-*" / "resources" / "native-binary" / name)
    candidates = sorted(glob.glob(pattern), key=os.path.getmtime)
    return candidates[-1] if candidates else None


def _claude_logged_in(binary):
    """claude auth status 會回一段 JSON，裡面有 loggedIn。回傳 True / False；查不出來（例如舊版）回傳 None。"""
    try:
        result = _run([binary, "auth", "status"], "", None, 30)
        return bool(json.loads(result.stdout)["loggedIn"])
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return None


def _claude(system_prompt, prompt, server=None):
    command = [
        _binary, "-p",
        "--output-format", "json",
        "--tools", "",               # 關掉所有內建工具：不能讀檔、不能執行指令、不能上網
        "--strict-mcp-config",       # 不載入你自己設定的其他 MCP 伺服器
        "--disable-slash-commands",
        "--no-session-persistence",
        "--system-prompt", system_prompt,
    ]
    if _model:
        command += ["--model", _model]
    env = os.environ.copy()
    env.pop("CLAUDECODE", None)  # 從 Claude Code 的終端機裡執行時也能用
    with tempfile.TemporaryDirectory() as empty_dir, tempfile.TemporaryDirectory() as config_dir:
        if server:
            # 只接上我們的工具伺服器，並允許它的工具（mcp__privacy__*）不用再問
            config = Path(config_dir) / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {"privacy": {"command": server[0], "args": server[1:]}}}),
                              encoding="utf-8")
            command += ["--mcp-config", str(config), "--allowedTools", "mcp__privacy"]
        result = _run(command, prompt, empty_dir, AGENT_TIMEOUT if server else TIMEOUT, env)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip()[:300])
    output = json.loads(result.stdout)
    if output.get("is_error"):
        raise RuntimeError(str(output.get("result"))[:300])
    return output.get("result", "")


# ---------- Codex CLI ----------

# Codex 內建的工具功能（執行指令、瀏覽器、操作電腦、外掛、分身…），只要這個版本有，就全部關掉。
# 不關 code mode：新版 Codex 透過它呼叫所有工具（包括我們的 MCP 工具），它的 JavaScript 環境
# 沒有 require、process、fetch，讀不到檔案也連不上網路（2026-11 用 Codex 0.166 實測）。
CODEX_BLOCKED_FEATURES = [
    "shell_tool", "unified_exec", "apps", "plugins", "remote_plugin", "browser_use", "browser_use_external",
    "in_app_browser", "computer_use", "image_generation", "view_image", "multi_agent", "multi_agent_v2",
    "tool_suggest", "skill_search", "skill_mcp_dependency_install", "sleep_tool", "goals", "hooks", "memories",
    "js_repl", "request_permissions_tool", "standalone_web_search", "workspace_dependencies",
]
# 執行紀錄裡允許出現的項目；其他任何項目（執行指令、改檔案、上網搜尋…）都算違規，這次結果作廢
CODEX_ALLOWED_ITEMS = {"agent_message", "reasoning", "todo_list", "error"}


def find_codex():
    if os.environ.get("CODEX_BIN"):
        return os.environ["CODEX_BIN"]
    found = shutil.which("codex")
    if found and os.name == "nt" and not found.lower().endswith(".exe"):
        # npm 裝的 codex 是批次檔，參數經過 cmd.exe 可能被改掉，所以直接找裡面的執行檔
        prefix = Path(found).parent / "node_modules"
        patterns = [prefix / "@openai" / "codex" / "node_modules" / "@openai" / "codex-win32-*" / "vendor" / "*" / "bin" / "codex.exe",
                    prefix / "@openai" / "codex-win32-*" / "vendor" / "*" / "bin" / "codex.exe"]
        found = next((hit for pattern in patterns for hit in glob.glob(str(pattern))), None)
    if found:
        return found
    # VS Code 的 Codex 擴充套件內附的執行檔
    name = "codex.exe" if os.name == "nt" else "codex"
    candidates = sorted(glob.glob(str(Path.home() / ".vscode" / "extensions" / "openai.chatgpt-*" / "bin" / "*" / name)),
                        key=os.path.getmtime)
    return candidates[-1] if candidates else None


def _codex_logged_in(binary):
    """codex login status：登入了回傳 0。回傳 True / False；查不出來回傳 None。"""
    if os.environ.get("CODEX_API_KEY"):
        return True  # 用 API 金鑰的話 codex exec 可以直接用，但 login status 會說沒登入
    try:
        result = _run([binary, "login", "status"], "", None, 30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return True
    return False if "not logged in" in (result.stdout + result.stderr).lower() else None


def _codex_features_to_disable():
    try:
        result = _run([_binary, "features", "list"], None, None, 60)
    except (OSError, subprocess.TimeoutExpired):
        return list(CODEX_BLOCKED_FEATURES)
    known = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    return [f for f in CODEX_BLOCKED_FEATURES if f in known]


def _toml(value):
    return json.dumps(value, ensure_ascii=False)  # JSON 的字串和陣列寫法也是合法的 TOML


def codex_violations(events, allow_mcp):
    """從 codex exec --json 的執行紀錄找出不允許的動作。"""
    problems = set()
    for event in events:
        item = event.get("item") or {}
        kind = item.get("type")
        if not kind or kind in CODEX_ALLOWED_ITEMS:
            continue
        if kind == "mcp_tool_call" and allow_mcp and item.get("server") == "privacy":
            continue
        problems.add(f"{kind}（{item.get('server')}）" if kind == "mcp_tool_call" else kind)
    return sorted(problems)


def _codex(system_prompt, prompt, server=None):
    with tempfile.TemporaryDirectory() as empty_dir, tempfile.TemporaryDirectory() as out_dir:
        last_message = Path(out_dir) / "last_message.txt"
        command = [
            _binary, "exec",
            "--ignore-user-config",      # 不載入你自己的設定（其他 MCP 伺服器、外掛）
            "--ignore-rules",
            "--skip-git-repo-check",
            "--ephemeral",               # 不在電腦上留下對話紀錄
            "--sandbox", "read-only",
            "--color", "never",
            "--json",                    # 輸出執行紀錄，用來檢查 AI 有沒有用到不允許的功能
            "--output-last-message", str(last_message),
            "--cd", empty_dir,
            "-c", 'approval_policy="never"',
            "-c", 'web_search="disabled"',
            "-c", "agents.enabled=false",  # 不能再叫出其他 AI 分身
            "-c", f'model_reasoning_effort="{"medium" if server else "low"}"',
        ]
        for feature in _codex_disabled:
            command += ["--disable", feature]
        if server:
            command += ["-c", f"mcp_servers.privacy.command={_toml(server[0])}",
                        "-c", f"mcp_servers.privacy.args={_toml(server[1:])}",
                        "-c", "mcp_servers.privacy.tool_timeout_sec=120"]
        if _model:
            command += ["--model", _model]
        command.append("-")  # 題目從 stdin 讀，不放在指令列上
        result = _run(command, system_prompt + "\n\n" + prompt, empty_dir, AGENT_TIMEOUT if server else TIMEOUT)
        events = []
        for line in result.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        problems = codex_violations(events, allow_mcp=bool(server))
        if problems:
            raise RuntimeError(f"AI 用了不允許的功能（{'、'.join(problems)}），這次結果作廢")
        errors = [e.get("message") or (e.get("error") or {}).get("message") for e in events
                  if e.get("type") in ("error", "turn.failed")]
        if result.returncode != 0 or not last_message.exists():
            raise RuntimeError(str(next((e for e in errors if e), None) or result.stderr.strip())[:300])
        return last_message.read_text(encoding="utf-8")


# ---------- Gemini API ----------

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_PREFERRED = ["gemini-flash-latest"]  # Google 維護的別名，永遠指向最新的 Flash 模型
GEMINI_MAX_TURNS = 40


def gemini_api_key():
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    path = BASE / "secrets" / "gemini_api_key.txt"
    if not key and path.exists():
        key = path.read_text(encoding="utf-8").strip()
    return key or None


def _gemini(method, path, body=None):
    request = urllib.request.Request(
        f"{GEMINI_BASE}/{path}", method=method,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json", "x-goog-api-key": _api_key})  # 金鑰放在標頭，不放在網址
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        try:
            detail = json.loads(detail)["error"]["message"]
        except (ValueError, KeyError, TypeError):
            pass
        raise RuntimeError(f"Gemini API 回應 {error.code}：{detail[:300]}") from None


def _gemini_pick_model():
    data = _gemini("GET", "models?pageSize=1000")
    names = [m["name"].split("/", 1)[-1] for m in data.get("models", [])
             if "generateContent" in m.get("supportedGenerationMethods", [])]
    for name in GEMINI_PREFERRED:
        if name in names:
            return name
    flash = [n for n in names if re.fullmatch(r"gemini-[\d.]+-flash", n)]
    if flash:
        return max(flash, key=lambda n: [int(x) for x in re.findall(r"\d+", n)])
    if names:
        return names[0]
    raise RuntimeError("這把金鑰沒有可以用的模型")


def _gemini_generate(body):
    response = _gemini("POST", f"models/{_model}:generateContent", body)
    candidates = response.get("candidates") or []
    if not candidates or not candidates[0].get("content", {}).get("parts"):
        reason = (candidates[0].get("finishReason") if candidates else None) or response.get("promptFeedback")
        raise RuntimeError(f"Gemini 沒有回覆內容（{reason}）")
    content = candidates[0]["content"]
    content.setdefault("role", "model")
    return content


def _gemini_text(content):
    return "".join(part.get("text", "") for part in content["parts"] if not part.get("thought"))


def _gemini_complete(system_prompt, prompt):
    return _gemini_text(_gemini_generate({
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"},
    }))


def _gemini_investigate(system_prompt, prompt, box):
    """程式自己跑「AI 想查 → 程式用工具箱查 → 結果交回給 AI」的迴圈。AI 沒有工具箱以外的任何功能。"""
    import agent_tools
    base = {"systemInstruction": {"parts": [{"text": system_prompt}]},
            "tools": [{"functionDeclarations": agent_tools.declarations()}]}
    contents = [{"role": "user", "parts": [{"text": prompt}]}]
    for _ in range(GEMINI_MAX_TURNS):
        content = _gemini_generate({**base, "contents": contents})
        calls = [part["functionCall"] for part in content["parts"] if "functionCall" in part]
        if not calls:
            return _gemini_text(content)
        contents.append(content)  # 原封不動放回去：Gemini 3 需要裡面的 thoughtSignature
        responses = []
        for call in calls:
            response = {"name": call.get("name"), "response": box.call(call.get("name"), call.get("args"))}
            if call.get("id"):
                response["id"] = call["id"]
            responses.append({"functionResponse": response})
        contents.append({"role": "user", "parts": responses})
    raise RuntimeError("AI 調查的回合太多，已停止")
