"""實驗功能（AI 調查員、工具箱）的自我測試。

加 --agent 時才會跟著主程式的自我測試一起跑；python tests/known_answers.py 則是一次跑全部。
"""
import json
import tempfile
from pathlib import Path

from common import save_json
from tests.known_answers import quiet_guard


def t_tool_guard():
    from experimental import agent_tools
    with tempfile.TemporaryDirectory() as folder, quiet_guard(folder):
        save_json(Path(folder) / "shops165.json", [
            {"shop_name": "好物客服 demo@example.com", "times": 1, "last_listed": "2026-10-01"},
            {"shop_name": "好物商店", "times": 2, "last_listed": "2026-10-08"}])
        box = agent_tools.ToolBox(folder, run_id="test")
        blocked = box.call("search_165", {"keyword": "好物客服"})
        normal = box.call("search_165", {"keyword": "好物商店"})
        unknown = box.call("read_file", {"path": "secrets/passwords.csv"})
        logged = agent_tools.load_calls(folder, "test")
    ok = ("海關攔截" in blocked.get("error", "") and normal.get("total") == 1 and "error" in unknown
          and list(logged) == ["T1", "T2", "T3"])
    return ok, ("回傳含 email 就擋下、正常查詢照常、沒有的工具不能用、每次呼叫都有編號和紀錄" if ok
                else f"結果不對：{blocked}、{normal}、{unknown}、{list(logged)}")


def t_parallel_calls():
    from experimental import agent_tools
    from concurrent.futures import ThreadPoolExecutor
    with tempfile.TemporaryDirectory() as folder, quiet_guard(folder):
        save_json(Path(folder) / "shops165.json", [{"shop_name": "好物商店", "times": 1, "last_listed": "2026-10-01"}])
        box = agent_tools.ToolBox(folder, run_id="test")
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: box.call("search_165", {"keyword": "好物"}), range(20)))
        logged = agent_tools.load_calls(folder, "test")
    ids = {r["call_id"] for r in results}
    ok = len(ids) == 20 and list(logged) == [f"T{i}" for i in range(1, 21)]
    return ok, "同時呼叫 20 次，編號不重複、紀錄沒有遺漏" if ok else f"結果不對：{sorted(ids)}、{list(logged)}"


def t_citation_check():
    from experimental.investigate import verify
    accounts = [{"domain": "bnext.com.tw", "sources": [], "still_using": True, "first_seen": None}]
    breach = {"breach_name": "Bnext Media", "breach_domain": "bnextmedia.com", "breach_date": "2020-01-01",
              "data_classes": ["Email addresses", "Passwords"], "pwn_count": 1000}
    calls = {"T1": {"call_id": "T1", "tool": "search_breaches", "args": {"keyword": "bnext"},
                    "result": {"call_id": "T1", "total": 1, "matches": [breach]}},
             "T2": {"call_id": "T2", "tool": "search_breaches", "args": {"keyword": "other"},
                    "result": {"call_id": "T2", "total": 0, "matches": []}}}
    claims = [
        {"type": "breach", "domain": "bnext.com.tw", "breach_name": "Bnext Media",
         "reason": "bnextmedia.com 是同一家公司的網域", "sources": ["T1"]},                      # 有依據：採用
        {"type": "breach", "domain": "bnext.com.tw", "breach_name": "Made Up", "reason": "猜的", "sources": ["T2"]},
        {"type": "breach", "domain": "bnext.com.tw", "breach_name": "Bnext Media", "reason": "同一家", "sources": ["T9"]},
        {"type": "breach", "domain": "evil.com", "breach_name": "Bnext Media", "reason": "同一家", "sources": ["T1"]},
        {"type": "note", "id": "B9", "note": "先換密碼", "sources": ["T1"]},
    ]
    new_items, accepted, rejected = verify(claims, calls, [], accounts)
    ok = (len(new_items) == 1 and new_items[0]["id"] == "B1" and new_items[0]["ai_guess"]
          and new_items[0]["default_level"] == "yellow" and len(accepted) == 1 and len(rejected) == 4)
    return ok, ("有依據的結論才採用（1 個）；編造、引用不存在的查詢、別人的網域都被刪掉（4 個）" if ok
                else f"結果不對：採用 {accepted}、刪除 {rejected}")


def t_gemini_loop():
    from experimental import agent_tools
    import llm
    from experimental import agent_llm
    replies = [
        {"candidates": [{"content": {"role": "model", "parts": [
            {"functionCall": {"name": "search_165", "args": {"keyword": "好物"}}, "thoughtSignature": "sig-1"}]}}]},
        {"candidates": [{"content": {"role": "model", "parts": [{"text": "[]"}]}}]},
    ]
    sent = []

    def fake_gemini(method, path, body=None):
        sent.append(json.loads(json.dumps(body)))  # 複製一份，之後的修改不影響紀錄
        return replies[len(sent) - 1]

    original = llm._gemini
    with tempfile.TemporaryDirectory() as folder, quiet_guard(folder):
        save_json(Path(folder) / "shops165.json", [{"shop_name": "好物商店", "times": 1, "last_listed": "2026-10-01"}])
        llm._gemini = fake_gemini
        try:
            answer = agent_llm.gemini_investigate("system", "請調查", agent_tools.ToolBox(folder, run_id="test"))
        finally:
            llm._gemini = original
    contents = sent[-1]["contents"] if len(sent) == 2 else []
    reply = contents[2]["parts"][0]["functionResponse"]["response"] if len(contents) == 3 else {}
    ok = (answer == "[]" and contents[1]["parts"][0].get("thoughtSignature") == "sig-1"
          and reply.get("call_id") == "T1" and reply.get("total") == 1)
    return ok, "AI 要求查詢 → 程式用工具箱查 → 結果正確交回 AI" if ok else f"結果不對：{answer}、{contents}"


TESTS = [
    ("工具箱：海關", t_tool_guard),
    ("工具箱：同時呼叫", t_parallel_calls),
    ("AI 調查：依據檢查", t_citation_check),
    ("Gemini 工具迴圈（模擬）", t_gemini_loop),
]
