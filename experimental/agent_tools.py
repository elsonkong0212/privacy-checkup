"""AI 調查員的工具箱（--agent 模式，以及接到你自己的 AI 工具時使用）。

AI 只能透過這幾個工具查資料：全部只能讀、不能改，也不會連到你帳號所在的網站。
兩種接法用的是同一套工具：
- Claude Code、Codex 等支援 MCP 的 AI 工具：透過 mcp_server.py
- Gemini API：由 agent_llm.py 直接把工具交給 AI

每次呼叫都會：
1. 編號（T1、T2…）：AI 寫結論時要引用這個編號，程式再回頭檢查依據
2. 過海關：只回傳白名單欄位；疑似有敏感資料就整筆擋下
3. 留紀錄：寫進資料夾裡的 tool_calls.jsonl（給程式檢查依據）和 audit.log（給你檢查）
4. 算次數：超過上限就不再回答
"""
import contextlib
import json
import re
import sys
import threading
import time
from pathlib import Path

import guard
from common import normalize_domain
from stages import breach_match, remedy

MAX_CALLS = 30
CALL_LOG = "tool_calls.jsonl"

SERVER_INSTRUCTIONS = (
    "個人資安健檢的查詢工具（全部唯讀）。可以列出使用者的帳號和健檢結果、查某個網站的密碼狀況、"
    "搜尋已公開的外洩事件和 165 高風險賣場名單、查兩步驟驗證和刪除帳號的方法。"
    "工具不會回傳密碼、帳號名稱或 email。每次回傳都有 call_id，引用查到的結果時請附上。"
)

SPECS = {
    "list_accounts": {
        "description": "列出使用者的所有帳號：網域、是否還在使用、最早收到這個網站來信的日期（大約等於註冊時間）。",
        "params": {},
    },
    "list_findings": {
        "description": "列出健檢找到的問題（外洩的密碼、重複使用的密碼、外洩事件、165 高風險賣場、"
                       "可以開兩步驟驗證、建議刪除），含燈號。",
        "params": {},
    },
    "check_password": {
        "description": "查某個網站的密碼狀況：強度、在外洩密碼庫出現的次數、和哪些網站共用同一組密碼。不會回傳密碼本身。",
        "params": {"domain": "網站的網域，例如 shopee.tw"},
    },
    "search_breaches": {
        "description": "用關鍵字搜尋 HIBP 收錄的已公開外洩事件（比對事件名稱和網域，大多是英文），"
                       "用來找名稱或網址和帳號不一樣、但可能是同一家的外洩事件。",
        "params": {"keyword": "英文關鍵字，例如品牌名、舊名稱、母公司名稱"},
    },
    "search_165": {
        "description": "用關鍵字搜尋 165 全民防騙網公布的高風險賣場名單（店名大多是中文）。",
        "params": {"keyword": "店名關鍵字，中文或英文，例如 蝦皮、shopee"},
    },
    "get_remedies": {
        "description": "查某個網站支援哪些兩步驟驗證方式，以及刪除帳號的難易度和說明連結。",
        "params": {"domain": "網站的網域"},
    },
}


def declarations():
    """給 Gemini API 的工具說明（function declarations）。"""
    result = []
    for name, spec in SPECS.items():
        item = {"name": name, "description": spec["description"]}
        if spec["params"]:
            item["parameters"] = {
                "type": "object",
                "properties": {p: {"type": "string", "description": d} for p, d in spec["params"].items()},
                "required": list(spec["params"]),
            }
        result.append(item)
    return result


def load_calls(data_dir, run_id):
    """讀出某一次調查的所有工具呼叫（call_id → 紀錄），用來檢查 AI 的結論有沒有依據。"""
    path = Path(data_dir) / CALL_LOG
    if not path.exists():
        return {}
    calls = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.get("run") == run_id:
            calls[record["call_id"]] = record
    return dict(sorted(calls.items(), key=lambda item: int(item[0][1:])))  # 同時呼叫時寫入順序會亂，照編號排


def _drop_empty(data):
    return {k: v for k, v in data.items() if v is not None}


def _domain(value):
    return normalize_domain(value) or value.strip().lower()


class ToolBox:
    def __init__(self, data_dir, run_id="chat", findings_file=None, max_calls=MAX_CALLS):
        self.data_dir = Path(data_dir)
        self.run_id = run_id
        self.findings_file = findings_file  # 調查模式讀 evidence.json；平常讀上一次的最終結果
        self.max_calls = max_calls
        self.count = 0
        self._indexes = None
        self._lock = threading.Lock()  # AI 可能同時呼叫好幾個工具，編號和紀錄不能撞在一起

    def call(self, name, args=None):
        args = args if isinstance(args, dict) else {}
        with self._lock:
            self.count += 1
            number = self.count
        call_id = f"T{number}"
        if number > self.max_calls:
            result = {"error": f"已經查了 {self.max_calls} 次，達到上限。請根據目前查到的結果作答。"}
        elif name not in SPECS:
            result = {"error": f"沒有 {name} 這個工具"}
        elif any(p not in args for p in SPECS[name]["params"]):
            result = {"error": "缺少參數：" + "、".join(SPECS[name]["params"])}
        else:
            try:
                with contextlib.redirect_stdout(sys.stderr):  # MCP 用 stdout 傳訊息，工具裡的 print 不能混進去
                    result = getattr(self, "_" + name)(**{p: str(args[p]) for p in SPECS[name]["params"]})
            except Exception as error:
                result = {"error": f"查詢失敗：{error}"}
        result = {"call_id": call_id, **guard.check_tool_result(f"AI 調查：{name}", result)}
        self._log(call_id, name, args, result)
        return result

    def _log(self, call_id, name, args, result):
        record = {"run": self.run_id, "call_id": call_id, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "tool": name, "args": args, "result": result}
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with open(self.data_dir / CALL_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            guard.audit("工具", f"AI 調查：{name}", json.dumps({"args": args, "result": result}, ensure_ascii=False))

    def _json(self, name):
        # 每次都重新讀：接在 VS Code 這類工具上時伺服器會一直開著，重跑健檢後要讀到新結果
        path = self.data_dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    # ---------- 工具 ----------

    def _list_accounts(self):
        accounts = self._json("accounts.json")
        if accounts is None:
            return {"error": "還沒有健檢結果，請先執行 python main.py"}
        return {"dataset": "示範資料" if self.data_dir.name == "demo" else "使用者自己的資料", "accounts": [
            {"domain": a["domain"], "still_using": a.get("still_using"), "first_seen": a.get("first_seen"),
             "sources": a.get("sources", [])} for a in accounts]}

    def _list_findings(self):
        for name in [self.findings_file] if self.findings_file else ["final.json", "evidence.json"]:
            items = self._json(name)
            if items is not None:
                return {"findings": [{**e, "level": e.get("level") or e.get("default_level")} for e in items]}
        return {"error": "還沒有健檢結果，請先執行 python main.py"}

    def _check_password(self, domain):
        domain = _domain(domain)
        summary = self._json("passwords_summary.json") or []
        mine = [s for s in summary if s["domain"] == domain]
        if not mine:
            return {"domain": domain, "note": "密碼檔裡沒有這個網站的密碼"}
        groups = {}
        for s in summary:
            if s.get("reuse_group"):
                groups.setdefault(s["reuse_group"], set()).add(s["domain"])
        return {"domain": domain, "passwords": [
            {"strength": s["strength_label"], "pwned_count": s["pwned_count"], "reused": s["reused"],
             "shared_with": sorted(groups.get(s.get("reuse_group"), set()) - {domain})} for s in mine]}

    def _search_breaches(self, keyword):
        word = keyword.strip().casefold()
        if len(word) < 2:
            return {"error": "關鍵字至少要 2 個字"}
        breaches, _, _ = breach_match.load_breaches()
        matches = [b for b in breaches if any(word in (b.get(k) or "").casefold() for k in ("Name", "Title", "Domain"))]
        return {"keyword": keyword, "total": len(matches), "matches": [
            _drop_empty({"breach_name": b["Title"], "breach_domain": b.get("Domain") or None,
                         "breach_date": b["BreachDate"], "data_classes": b["DataClasses"], "pwn_count": b["PwnCount"]})
            for b in matches[:10]]}

    def _search_165(self, keyword):
        word = re.sub(r"\s+", "", keyword).casefold()
        if len(word) < 2:
            return {"error": "關鍵字至少要 2 個字"}
        shops = self._json("shops165.json")
        if shops is None:
            return {"error": "沒有 165 名單，請先執行 python main.py"}
        matches = [s for s in shops if word in re.sub(r"\s+", "", s["shop_name"]).casefold()]
        return {"keyword": keyword, "total": len(matches), "matches": [
            _drop_empty({"shop_name": s["shop_name"], "times": s.get("times"), "last_listed": s.get("last_listed")})
            for s in matches[:15]]}

    def _get_remedies(self, domain):
        domain = _domain(domain)
        if self._indexes is None:
            self._indexes = remedy.load_indexes()
        tfa_index, jdm_index, _ = self._indexes
        info, site = tfa_index.get(domain), jdm_index.get(domain)
        if info is None and site is None:
            return {"domain": domain, "note": "2fa.directory 和 JustDeleteMe 都沒有收錄這個網站"}
        url = (site or {}).get("url")
        if url and not url.lower().startswith("http"):
            url = None  # 有些是寫給客服的 mailto 連結（含 email），不回傳
        notes = []
        if info is None:
            notes.append("2fa.directory 沒有收錄，不確定能不能開兩步驟驗證")
        if site is None:
            notes.append("JustDeleteMe 沒有收錄刪除方法")
        return _drop_empty({"domain": domain,
                            "two_factor_methods": None if info is None else info.get("methods", []),
                            "two_factor_doc": (info or {}).get("documentation"),
                            "delete_difficulty": (site or {}).get("difficulty"), "delete_url": url,
                            "note": "；".join(notes) or None})
