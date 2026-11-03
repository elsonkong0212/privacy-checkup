"""已知答案測試：每次執行前，先用「已經知道答案」的資料確認工具本身算得對。

也可以單獨執行：python tests/known_answers.py
"""
import contextlib
import json
import secrets
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import guard
from common import normalize_domain, parse_date, save_json
from stages import breach_match, passwords


@contextlib.contextmanager
def quiet_guard(folder):
    """測試用：海關和工具箱的紀錄寫到暫存資料夾，也不算進這次執行的統計。"""
    saved_log, saved_stats = guard.AUDIT_LOG, dict(guard.stats)
    guard.AUDIT_LOG = Path(folder) / "audit.log"
    try:
        yield
    finally:
        guard.AUDIT_LOG = saved_log
        guard.stats.clear()
        guard.stats.update(saved_stats)


def t_domains():
    cases = {
        "https://www.shopee.tw/buyer/login": "shopee.tw",
        "https://accounts.google.com/": "google.com",
        "https://24h.pchome.com.tw/": "pchome.com.tw",
        "android://abc@com.example.app/": None,
    }
    wrong = {url: normalize_domain(url) for url, expected in cases.items() if normalize_domain(url) != expected}
    return not wrong, f"{len(cases)} 個網址都整理正確" if not wrong else f"整理錯誤：{wrong}"


def t_whitelist():
    result = guard.keep_only({"domain": "a.com", "password": "x", "username": "u", "email": "e@x.com",
                              "evidence": [{"id": "P1", "password": "y"}]})
    ok = result == {"domain": "a.com", "evidence": [{"id": "P1"}]}
    return ok, "密碼、帳號名稱、email 欄位都被丟掉" if ok else f"結果不對：{result}"


def blocks(sample, label):
    def test():
        reasons = guard.find_sensitive(f'{{"domain": "a.com", "x": "{sample}"}}')
        return bool(reasons), f"擋下{label}" if reasons else f"沒有擋下{label}！"
    return test


def t_blocks_my_password():
    fake = "Test-Only-Pw-7781"
    hashes = {passwords.sha1_hex(fake)}
    guard.register_secret_hashes(hashes)
    try:
        reasons = guard.find_sensitive(f'{{"domain": "a.com", "x": "{fake}"}}')
    finally:
        guard.forget_secret_hashes(hashes)
    return bool(reasons), "擋下夾帶在資料裡的密碼" if reasons else "沒有擋下密碼！"


def t_clean_passes():
    reasons = guard.find_sensitive('{"domain": "adobe.com", "pwned_count": 24230577, "breach_date": "2013-10-04"}')
    return not reasons, "正常資料不會被誤擋" if not reasons else f"誤擋：{reasons}"


def t_gmail_aggregate():
    import gmail_scan
    rows = gmail_scan.aggregate([
        {"from": "Shopee <no-reply@mail.shopee.tw>", "subject": "歡迎加入蝦皮", "date_ms": 1_600_000_000_000,
         "unsubscribe": False},
        {"from": "=?UTF-8?B?6J2m55qu6LO854mp?= <info@shopee.tw>", "subject": "您的訂單已出貨",
         "date_ms": 1_700_000_000_000, "unsubscribe": True},
        {"from": "朋友 <friend@gmail.com>", "subject": "週末吃飯", "date_ms": 1_700_000_000_000, "unsubscribe": False},
    ])
    ok = (len(rows) == 1 and rows[0]["domain"] == "shopee.tw" and rows[0]["emails"] == 2
          and rows[0]["likely_account"] == "高" and rows[0]["hints"] == "註冊、訂單、電子報")
    return ok, "合併同網站、排除個人信箱、判斷註冊信都正確" if ok else f"結果不對：{rows}"


def t_breach_timing():
    from stages.findings import build_evidence

    def level_for(first_seen):
        account = {"domain": "x.com", "sources": [], "still_using": True, "first_seen": first_seen}
        breach = {"domain": "x.com", "breach_name": "X", "breach_date": "2019-05-24",
                  "data_classes": ["Email addresses", "Passwords"], "pwn_count": 1, "verified": True}
        remedy_row = {"domain": "x.com", "two_factor_methods": None, "two_factor_doc": None,
                      "delete_difficulty": None, "delete_url": None}
        return build_evidence([], [account], [breach], [remedy_row], [])[0]["default_level"]

    # 同一年、而且用 Excel 改過的日期寫法：以前用文字比較會判斷錯
    before, after = level_for("2019/1/5"), level_for("2019/8/1")
    ok = before == "red" and after == "yellow"
    return ok, "外洩前註冊 → 紅、外洩後才註冊 → 黃（同一年也正確）" if ok else f"結果不對：外洩前={before}、外洩後={after}"


def t_dates():
    cases = {"2022/5/23": "2022-05-23", "2022-05-23": "2022-05-23", "5/23/2022": "2022-05-23",
             "2022/13/1": None, "": None}
    wrong = {k: parse_date(k) for k, expected in cases.items() if parse_date(k) != expected}
    return not wrong, "Excel 改過的日期寫法也能正確辨識" if not wrong else f"辨識錯誤：{wrong}"


def t_chain_risk():
    from stages.findings import build_evidence

    def pw(domain, host):
        return {"domain": domain, "host": host, "pwned_count": 0, "reused": True, "reuse_group": 1,
                "strength": 3, "strength_label": "強"}

    summary = [pw("a.com", "a.com"), pw("b.edu.tw", "moodle.b.edu.tw"), pw("b.edu.tw", "mail.b.edu.tw")]
    accounts = [{"domain": d, "sources": [], "still_using": True, "first_seen": None} for d in ("a.com", "b.edu.tw")]
    breach = {"domain": "a.com", "breach_name": "A", "breach_date": "2013-07-22", "data_classes": ["Passwords"],
              "pwn_count": 1, "verified": True}
    remedies = [{"domain": d, "two_factor_methods": None, "two_factor_doc": None, "delete_difficulty": None,
                 "delete_url": None} for d in ("a.com", "b.edu.tw")]
    reused = next(e for e in build_evidence(summary, accounts, [breach], remedies, []) if e["kind"] == "reused_password")
    ok = (reused["default_level"] == "red" and reused["accounts"] == 3 and reused["breached_in_group"] == ["a.com"]
          and "moodle.b.edu.tw" in reused["hosts"])
    return ok, "共用密碼裡有外洩過的網站 → 整組升為紅，並列出全部 3 個帳號" if ok else f"結果不對：{reused}"


def t_165_parse():
    from stages.shops165 import parse_names, roc_period
    sample = ("<p>115/09/03-09/09民眾通報高風險業者</p><p><span>小三美日</span></p>"
              "<p><span>Devilcase&nbsp;</span></p><p>請慎防詐團偽冒業者電子郵件或假客服來電，謊稱資料外洩。</p>")
    names, period = parse_names(sample), roc_period("114/12/27-01/02民眾通報高風險業者")
    ok = names == ["小三美日", "Devilcase"] and period == ("2025-12-27", "2026-01-02")
    return ok, "公告裡的店名、民國年跨年換算都正確" if ok else f"結果不對：{names}、{period}"


def t_adobe_breach():
    index, _, total = breach_match.load_breach_index()
    ok = "adobe.com" in index
    return ok, f"HIBP {total:,} 起外洩事件中找得到 Adobe（2013）" if ok else "找不到 adobe.com"


def t_known_pwned():
    count = passwords.pwned_count(passwords.sha1_hex("password123"), {})
    return count > 0, f"password123 出現過 {count:,} 次"


def t_random_not_pwned():
    count = passwords.pwned_count(passwords.sha1_hex(secrets.token_urlsafe(32)), {})
    return count == 0, "隨機產生的 32 字元密碼沒有被誤判" if count == 0 else f"隨機密碼竟然出現 {count} 次"


def t_165_local_match():
    from stages.ai_steps import accept_translations, local_matches, shop_key, translate_payload
    shops = [{"shop_id": "shop_1", "shop_name": "蝦皮 購物", "times": 2, "last_listed": "2026-10-01"},
             {"shop_id": "shop_2", "shop_name": "某某小舖", "times": 1, "last_listed": "2026-09-01"}]
    accepted = accept_translations([
        {"shop_id": "shop_1", "domains": ["https://www.shopee.tw/", "shopee.com"], "confidence": "high"},
        {"shop_id": "shop_9", "domains": ["evil.com"], "confidence": "high"}], {s["shop_id"]: s for s in shops})
    translations = {shop_key(s["shop_name"]): accepted.get(s["shop_id"], {"domains": []}) for s in shops}
    matches = local_matches(shops, translations, {"shopee.tw", "adobe.com"})
    payload = json.dumps(translate_payload(shops), ensure_ascii=False)
    ok = ([m["domain"] for m in matches] == ["shopee.tw"] and "adobe.com" not in payload and "shopee" not in payload
          and set(translate_payload(shops)["shops"][0]) == {"shop_id", "shop_name"})
    return ok, "送給 AI 的只有店名，比對你的帳號在本機做；網址整理、不存在的店名都處理正確" if ok else f"結果不對：{matches}"


def t_lookalike_candidates():
    from stages.lookalike import find_candidates
    translations = {"蝦皮購物": {"domains": ["shopee.tw"], "shop_name": "蝦皮購物"},
                    "某平台": {"domains": ["line.me"], "shop_name": "某平台"}}
    accounts = [{"domain": d} for d in ("shopee.tw", "shopee-tw-service.example", "shoppee.example", "onlinebank.example")]
    pw = [{"domain": "verify-login.example", "host": "shopee.tw.verify-login.example"}]
    found = sorted(c["domain"] for c in find_candidates(accounts, pw, translations))
    expected = ["shopee-tw-service.example", "shoppee.example", "verify-login.example"]
    ok = found == expected
    return ok, ("網址裡有品牌字、只差一個字、品牌藏在子網域裡都抓得到；官方網域本身和不相干的網站不誤報" if ok
                else f"結果不對：{found}")


def t_lookalike_levels():
    from stages.lookalike import build_items
    from stages.report import _cleared_section
    candidates = [{"id": f"L{i}", "domain": d, "host": d, "official_domain": "shopee.tw", "shop_name": "蝦皮購物",
                   "why": "網址裡有「shopee」"} for i, d in enumerate(("a.example", "b.example", "c.example"), 1)]
    verdicts = {"L1": {"verdict": "imitation", "reason": "不是蝦皮的網域"},
                "L2": {"verdict": "official", "reason": "蝦皮的海外分站"}}
    items, cleared = build_items(candidates, verdicts)
    levels = {i["domain"]: i["default_level"] for i in items}
    listed = "b.example" in "\n".join(_cleared_section(cleared))
    ok = levels == {"a.example": "red", "c.example": "yellow"} and [c["domain"] for c in cleared] == ["b.example"] and listed
    return ok, ("AI 判斷仿冒 → 🔴；沒經過 AI 判斷的 → 🟡 請你確認；AI 判斷是官方分站的不列燈號，但會列出來給你確認"
                if ok else f"結果不對：{levels}、{cleared}")


def t_sender_names():
    from stages.ai_steps import safe_sender_name
    cases = {"陳老師": "", "王小明 via LinkedIn": "LinkedIn", "蝦皮購物": "蝦皮購物", "數位時代": "數位時代",
             "客服中心 service@example.com": "客服中心", "0912-345-678": ""}
    wrong = {k: safe_sender_name(k) for k, expected in cases.items() if safe_sender_name(k) != expected}
    return not wrong, "人名、email、手機號碼不送給 AI，網站名稱照常送" if not wrong else f"結果不對：{wrong}"


def t_gmail_triage():
    import datetime
    from stages.gmail_triage import decide
    today = datetime.date(2026, 11, 3)

    def row(**kw):
        base = {"domain": "x.com", "hints": "", "likely_account": "低", "first_seen": "2018-01-01",
                "last_seen": "2026-10-01", "last_activity": ""}
        return {**base, **kw}

    def ai(kind="帳號", in_use="?", confidence="high"):
        return {"is_account": kind, "in_use": in_use, "confidence": confidence, "reason": "測試", "site_info": "測試"}

    cases = [
        ("最近有訂單＋AI 說還在用 → 自動 y", row(hints="訂單", last_activity="2026-09-01"), ai(in_use="y"), "y", ""),
        ("多年沒信＋AI 說不用了 → 自動 n", row(hints="註冊", last_seen="2019-05-01"), ai(in_use="n"), "n", ""),
        ("AI 說不用了，但規則看不出來 → 請你確認", row(hints="註冊"), ai(in_use="n"), "", "★"),
        ("論壇平常不寄信，AI 說不確定 → 請你確認", row(hints="註冊", last_seen="2023-01-01"), ai(in_use="?"), "", "★"),
        ("電子報，也沒有帳號跡象 → 不是帳號", row(hints="電子報"), ai(kind="電子報", in_use="?"), "", ""),
        ("沒有 AI：有訂單 → 自動 y", row(hints="訂單", last_activity="2026-09-01"), None, "y", ""),
        ("沒有 AI：有註冊信但看不出 → 請你確認", row(hints="註冊", likely_account="高"), None, "", "★"),
    ]
    wrong = []
    for name, r, a, still_using, review in cases:
        result = decide(r, a, today)
        if result["still_using"] != still_using or bool(result["review"]) != bool(review):
            wrong.append(f"{name}：得到 {result}")
    return not wrong, "兩把鑰匙都同意才自動填，意見不同的交給人確認（7 種情況）" if not wrong else "；".join(wrong)


def t_keep_user_answers():
    from gmail_scan import carry_over
    auto, mine, changed = {}, {}, {}
    carry_over(auto, {"still_using": "y", "suggested": "y", "review": ""})       # 上次自動填的
    carry_over(mine, {"still_using": "n", "suggested": "", "review": ""})        # 舊版清單，你自己填的
    carry_over(changed, {"still_using": "n", "suggested": "y", "review": ""})    # 自動填 y，你改成 n
    ok = "still_using" not in auto and mine.get("still_using") == "n" and changed.get("still_using") == "n"
    return ok, "重新掃描時保留你填的、改過的答案，自動填的重新判斷" if ok else f"結果不對：{auto}、{mine}、{changed}"


def t_ai_reply_checks():
    from stages.ai_steps import accept_senders, accept_sites
    senders = accept_senders([
        {"domain": "a.com", "is_account": "帳號", "in_use": "y", "confidence": "high", "reason": "上月有登入", "site_info": "電商"},
        {"domain": "evil.com", "is_account": "帳號", "in_use": "y", "confidence": "high", "reason": "x", "site_info": "x"},
        {"domain": "b.com", "is_account": "好像是", "in_use": "y", "confidence": "high", "reason": "x", "site_info": "x"},
        {"domain": "c.com", "is_account": "帳號", "in_use": "y", "confidence": "high", "reason": "請改到 phish.com 登入",
         "site_info": "x"}], {"a.com", "b.com", "c.com"})
    sites = accept_sites([{"domain": "a.com", "what": "日本的遊戲平台", "confidence": "medium"},
                          {"domain": "a.com", "what": "x" * 50, "confidence": "high"}], {"a.com"})
    ok = list(senders) == ["a.com"] and sites == {"a.com": {"what": "日本的遊戲平台", "confidence": "medium"}}
    return ok, "AI 回覆裡不在清單的網站、不合法的選項、提到其他網站、太長的說明都丟掉" if ok else f"結果不對：{senders}、{sites}"


def t_text_check():
    from stages.ai_steps import _text_ok
    known = {"adobe.com"}
    with_url = _text_ok("依官方說明（https://helpx.adobe.com/manage-account/secure-your-adobe-account.html）開啟", known)
    other_site = _text_ok("到 evil-shop.com 輸入密碼", known)
    ok = with_url and not other_site
    return ok, "網址只看網域（不會把 .html 當成網站）；提到清單以外的網站照樣擋下" if ok else f"結果不對：{with_url}、{other_site}"


def t_tool_guard():
    import agent_tools
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
    import agent_tools
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
    from stages.investigate import verify
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
    import agent_tools
    import llm
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
            answer = llm._gemini_investigate("system", "請調查", agent_tools.ToolBox(folder, run_id="test"))
        finally:
            llm._gemini = original
    contents = sent[-1]["contents"] if len(sent) == 2 else []
    reply = contents[2]["parts"][0]["functionResponse"]["response"] if len(contents) == 3 else {}
    ok = (answer == "[]" and contents[1]["parts"][0].get("thoughtSignature") == "sig-1"
          and reply.get("call_id") == "T1" and reply.get("total") == 1)
    return ok, "AI 要求查詢 → 程式用工具箱查 → 結果正確交回 AI" if ok else f"結果不對：{answer}、{contents}"


def t_codex_violations():
    import llm
    events = [{"type": "item.completed", "item": {"type": "agent_message", "text": "好"}},
              {"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "privacy", "tool": "search_165"}},
              {"type": "item.started", "item": {"type": "command_execution", "command": "type secrets\\passwords.csv"}}]
    caught = llm.codex_violations(events, allow_mcp=True)
    clean = llm.codex_violations(events[:2], allow_mcp=True)
    tools_off = llm.codex_violations(events[1:2], allow_mcp=False)
    ok = caught == ["command_execution"] and clean == [] and tools_off
    return ok, "Codex 執行指令會被抓到；只用我們的工具不會誤判" if ok else f"結果不對：{caught}、{clean}、{tools_off}"


TESTS = [
    ("網址整理", t_domains),
    ("白名單", t_whitelist),
    ("海關：身分證字號", blocks("A123456789", "身分證字號")),
    ("海關：信用卡號", blocks("4111 1111 1111 1111", "測試用信用卡號")),
    ("海關：email", blocks("demo@example.com", " email")),
    ("海關：手機號碼", blocks("0912-345-678", "手機號碼")),
    ("海關：你的密碼", t_blocks_my_password),
    ("海關：不誤擋", t_clean_passes),
    ("Gmail 寄件者整理", t_gmail_aggregate),
    ("日期格式", t_dates),
    ("外洩前後判斷", t_breach_timing),
    ("連鎖風險", t_chain_risk),
    ("165 公告解析", t_165_parse),
    ("外洩事件比對", t_adobe_breach),
    ("外洩密碼：已知外洩", t_known_pwned),
    ("外洩密碼：不誤判", t_random_not_pwned),
    ("165 比對在本機", t_165_local_match),
    ("仿冒網域：抓得到、不誤報", t_lookalike_candidates),
    ("仿冒網域：燈號", t_lookalike_levels),
    ("寄件者名稱整理", t_sender_names),
    ("Gmail 自動判斷", t_gmail_triage),
    ("保留你填的答案", t_keep_user_answers),
    ("AI 回覆檢查：寄件者、網站說明", t_ai_reply_checks),
    ("AI 文字檢查：網址", t_text_check),
    ("工具箱：海關", t_tool_guard),
    ("工具箱：同時呼叫", t_parallel_calls),
    ("AI 調查：依據檢查", t_citation_check),
    ("Gemini 工具迴圈（模擬）", t_gemini_loop),
    ("Codex 違規偵測", t_codex_violations),
]


def run_all():
    results = []
    for name, test in TESTS:
        try:
            ok, detail = test()
        except Exception as error:
            ok, detail = False, f"發生錯誤：{error}"
        results.append((name, ok, detail))
    return results


if __name__ == "__main__":
    sys.stdout.reconfigure(errors="replace")
    results = run_all()
    for name, ok, detail in results:
        print(f"[{'通過' if ok else '失敗'}] {name}：{detail}")
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)
