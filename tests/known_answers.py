"""已知答案測試：每次執行前，先用「已經知道答案」的資料確認工具本身算得對。

也可以單獨執行：python tests/known_answers.py（這時實驗功能 experimental/ 的測試也會一起跑）
"""
import contextlib
import io
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
    saved_log, saved_stats, saved_sent = guard.AUDIT_LOG, dict(guard.stats), list(guard.sent_log)
    guard.AUDIT_LOG = Path(folder) / "audit.log"
    try:
        yield
    finally:
        guard.AUDIT_LOG = saved_log
        guard.stats.clear()
        guard.stats.update(saved_stats)
        guard.sent_log[:] = saved_sent


def t_domains():
    cases = {
        "https://www.shopee.tw/buyer/login": "shopee.tw",
        "https://accounts.google.com/": "google.com",
        "https://24h.pchome.com.tw/": "pchome.com.tw",
        "android://abc@com.example.app/": None,
        # 尾碼有幾段是查 Public Suffix List 決定的：以前手寫的清單沒有 co.th，會把整個網站整理成 co.th
        "https://shopee.co.th/login": "shopee.co.th",
        "https://www.lazada.co.id/": "lazada.co.id",
        "https://moodle.ncku.edu.tw/login": "ncku.edu.tw",
        # 每個人各有一個子網域的平台：不同人的網站不能算成同一個
        "https://someone.github.io/blog": "someone.github.io",
        "https://shop-a.myshopify.com/": "shop-a.myshopify.com",
        "https://www.city.kobe.jp/": "city.kobe.jp",           # 清單裡的例外規則
        "https://login.shopee-tw-service.example/": "shopee-tw-service.example",  # 清單上沒有的尾碼
    }
    wrong = {url: normalize_domain(url) for url, expected in cases.items() if normalize_domain(url) != expected}
    return not wrong, f"{len(cases)} 個網址都整理正確（含 co.th、github.io 這類尾碼）" if not wrong else f"整理錯誤：{wrong}"


def t_whitelist():
    """白名單是每個工作各一份：翻店名那一步就算被塞進帳號網域也送不出去；沒登記的工作不能呼叫 AI。"""
    evidence = guard.keep_only({"domain": "a.com", "password": "x", "username": "u", "email": "e@x.com",
                                "evidence": [{"id": "P1", "password": "y", "note": "備註"}]},
                               guard.TASKS["explain"]["fields"])
    shops = guard.keep_only({"shops": [{"shop_id": "shop_1", "shop_name": "某某小舖", "domain": "a.com"}],
                             "domains": ["a.com"]}, guard.TASKS["translate_shops"]["fields"])
    try:
        guard.ask_llm("沒登記的工作", "system", "說明", {"domain": "a.com"})
        refused = False
    except guard.Blocked:
        refused = True
    ok = (evidence == {"domain": "a.com", "evidence": [{"id": "P1"}]}
          and shops == {"shops": [{"shop_id": "shop_1", "shop_name": "某某小舖"}]} and refused)
    return ok, ("密碼、帳號名稱、email、備註都被丟掉；翻店名那一步連網域都送不出去；沒登記的工作不能呼叫 AI" if ok
                else f"結果不對：{evidence}、{shops}、沒登記的工作被擋下={refused}")


def t_core_only():
    """主程式不會載入實驗功能：沒加 --agent 時，experimental/ 裡的程式和它要用的 mcp 套件完全不會被執行。"""
    import subprocess
    code = "import sys, main; print(sorted(m for m in sys.modules if m.split('.')[0] in ('experimental', 'mcp')))"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                            cwd=Path(__file__).resolve().parent.parent)
    loaded = result.stdout.strip()
    ok = result.returncode == 0 and loaded == "[]"
    return ok, ("載入整個主程式之後，experimental/ 裡的程式一個都沒有被載入" if ok
                else f"結果不對：{loaded or result.stderr[-200:]}")


def t_download_cache():
    """下載快取：沒過期不重抓；過期了但抓不到（或抓到看不懂的內容）就用舊的，不會把舊的蓋掉。"""
    import io
    import os
    import time
    import common
    calls = []

    def good():
        calls.append(1)
        return {"第幾次下載": len(calls)}

    def broken():
        raise OSError("連不上")

    saved = common.CACHE
    try:
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            common.CACHE = Path(folder)
            long_ago = time.time() - 3 * 86400
            first, _ = common.cached_json("a.json", fetch=good)
            again, _ = common.cached_json("a.json", fetch=good)       # 還沒過期：不重抓
            os.utime(Path(folder) / "a.json", (long_ago, long_ago))
            stale, _ = common.cached_json("a.json", fetch=broken)     # 過期了但抓不到：用舊的
            fresh, _ = common.cached_json("a.json", fetch=good)       # 過期了而且抓得到：換成新的
            keep, _ = common.cached_json("b.json", max_age_hours=None, fetch=good)
            os.utime(Path(folder) / "b.json", (long_ago, long_ago))
            kept, _ = common.cached_json("b.json", max_age_hours=None, fetch=broken)  # 不會過期的：不再下載
    finally:
        common.CACHE = saved
    ok = (first == again == stale == {"第幾次下載": 1} and fresh == {"第幾次下載": 2}
          and keep == kept == {"第幾次下載": 3} and len(calls) == 3)
    return ok, ("沒過期不重抓；過期了抓不到就用舊的；抓得到才換新的" if ok
                else f"結果不對：{first}、{again}、{stale}、{fresh}、{keep}、{kept}，下載了 {len(calls)} 次")


CHROME_HEADER = "name,url,username,password,note\n"


def t_export_detect():
    """只認瀏覽器匯出的密碼檔；帳號清單、Gmail 候選清單這類 CSV 不算；可以只找某個時間之後的。"""
    import os
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        (folder / "Chrome 密碼.csv").write_text(CHROME_HEADER + "a,https://a.example,me,password123,\n", encoding="utf-8")
        (folder / "my_accounts.csv").write_text("domain,still_using,note\na.example,y,\n", encoding="utf-8")
        old = folder / "logins.csv"
        old.write_text("url,username,password\nhttps://b.example,me,x\n", encoding="utf-8")
        os.utime(old, (1_600_000_000, 1_600_000_000))  # 假裝是 2020 年匯出的
        every = sorted(p.name for p in passwords.find_exports([folder]))
        recent = [p.name for p in passwords.find_exports([folder], newer_than=1_700_000_000)]
    ok = every == ["Chrome 密碼.csv", "logins.csv"] and recent == ["Chrome 密碼.csv"]
    return ok, "Chrome、Firefox 的匯出檔都認得，其他 CSV 不誤認；分得出新舊" if ok else f"結果不對：{every}、{recent}"


def t_wait_and_destroy():
    """程式先等，匯出的檔案一寫完就讀取；讀完刪掉，留下的只有雜湊值。舊的匯出檔不會被當成這次的。"""
    import os
    import threading
    import time
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        old = folder / "舊的.csv"
        old.write_text(CHROME_HEADER + "a,https://a.example,me,old-password,\n", encoding="utf-8")
        os.utime(old, (1_600_000_000, 1_600_000_000))
        since = time.time()
        new = folder / "Chrome 密碼.csv"
        writer = threading.Timer(0.3, lambda: new.write_text(
            CHROME_HEADER + "a,https://a.example,me,password123,\nb,https://b.example,me,password123,\n", encoding="utf-8"))
        writer.start()
        found = passwords.wait_for_export([folder], since, timeout=10, interval=0.1)
        writer.join()
        entries, secret_hashes, _ = passwords.read_entries(found) if found else ([], {}, 0)
        if found:
            passwords.destroy(found)
        gone = found is not None and not found.exists() and old.exists()
    plaintext_left = any("password123" in str(field) for entry in entries for field in entry)
    ok = found == new and gone and len(entries) == 2 and not plaintext_left and len(secret_hashes) == 1
    return ok, ("等到匯出才讀、讀完就刪；記憶體裡只剩雜湊值；舊檔案不會被誤認成這次的" if ok
                else f"結果不對：找到 {found}、刪掉了 {gone}、留下明文 {plaintext_left}")


def t_sync_folder():
    root = Path(tempfile.gettempdir()).anchor  # C:\ 或 /，不受這台電腦的資料夾影響
    cases = {
        f"{root}Users/me/OneDrive - 國立成功大學/privacy-checkup/secrets": "OneDrive",
        f"{root}Users/me/Dropbox/secrets": "Dropbox",
        f"{root}Users/me/Library/Mobile Documents/com~apple~CloudDocs/secrets": "iCloud",
        f"{root}data/privacy-checkup/secrets": None,
    }
    wrong = [path for path, service in cases.items() if passwords.sync_service(path) != service]
    return not wrong, "OneDrive、Dropbox、iCloud 這類會同步上雲端的資料夾都認得出來" if not wrong else f"認錯：{wrong}"


def t_without_passwords():
    """沒有檢查密碼的那一次：上次的密碼問題不能算成「解決了」，要留到下次有檢查時再比。"""
    from stages import history
    item = {"kind": "pwned_password", "domain": "a.com", "level": "red", "key": "pwned_password|a.com",
            "title": "a.com：密碼出現在外洩密碼庫"}
    breach = {"kind": "breach", "domain": "b.com", "level": "red", "key": "breach|b.com|B", "title": "b.com：外洩事件"}
    skipped = history.compare([item, breach], [breach], passwords_checked=False)
    with tempfile.TemporaryDirectory() as folder:
        history.save(Path(folder), [breach], "第二次", carry=skipped["unchecked"])
        kept = history.latest(Path(folder))["items"]
    later = history.compare(kept, [breach], passwords_checked=True)  # 下次有檢查，而且真的換掉了
    ok = (not skipped["resolved"] and [i["key"] for i in skipped["unchecked"]] == [item["key"]]
          and [i["key"] for i in later["resolved"]] == [item["key"]])
    return ok, ("沒檢查密碼時，上次的密碼問題不算解決；下次有檢查、確定不見了才算" if ok
                else f"結果不對：{skipped}、{later}")


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


def t_blocks_odd_passwords():
    """密碼裡有空白、標點、引號，或夾在一句話中間，都要擋得下來；同時不能誤擋正常資料。"""
    fakes = {"有空白": "Test only pw 7781", "有逗號和冒號": "Test,only:pw-7781", "有引號和反斜線": 'Test"only\\pw-7781',
             "有大括號": "Test{only}pw-7781", "很短": "Tp,7 1"}
    secrets_ = {passwords.sha1_hex(pw): len(pw.encode("utf-8")) for pw in fakes.values()}
    guard.register_secret_hashes(secrets_)
    try:
        def blocked(data):
            return bool(guard.find_sensitive(json.dumps(data, ensure_ascii=False), data))

        missed = [label for label, pw in fakes.items() if not blocked({"domain": "a.com", "sender_name": pw})]
        missed += [f"{label}（夾在句子裡）" for label, pw in fakes.items()
                   if label != "很短" and not blocked({"sender_name": f"你的密碼是{pw}喔"})]
        clean = not blocked({"domain": "adobe.com", "pwned_count": 24230577, "sender_name": "Test only 測試"})
    finally:
        guard.forget_secret_hashes(secrets_)
    ok = not missed and clean
    return ok, ("密碼含空白、逗號、引號、大括號，或夾在一句話中間都擋得下來；正常資料不誤擋" if ok
                else f"沒擋下：{missed}；正常資料{'沒有' if clean else '被'}誤擋")


def t_clean_passes():
    reasons = guard.find_sensitive('{"domain": "adobe.com", "pwned_count": 24230577, "breach_date": "2013-10-04"}')
    return not reasons, "正常資料不會被誤擋" if not reasons else f"誤擋：{reasons}"


def t_secrets_outside():
    """個人資料放在專案外面：舊版留在專案 secrets/ 的檔案會搬過去，新位置已經有的同名檔案不會被蓋掉。"""
    import io
    import os
    import common
    saved = common.SECRETS, common.OLD_SECRETS
    try:
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            common.OLD_SECRETS, common.SECRETS = Path(folder) / "project" / "secrets", Path(folder) / "home" / "mine"
            common.OLD_SECRETS.mkdir(parents=True)
            common.SECRETS.mkdir(parents=True)
            (common.OLD_SECRETS / "my_accounts.csv").write_text("舊的", encoding="utf-8")
            (common.OLD_SECRETS / "gmail_candidates.csv").write_text("舊的", encoding="utf-8")
            (common.SECRETS / "gmail_candidates.csv").write_text("新的", encoding="utf-8")
            common.prepare_secrets()
            moved = (common.SECRETS / "my_accounts.csv").exists() and not (common.OLD_SECRETS / "my_accounts.csv").exists()
            kept = ((common.SECRETS / "gmail_candidates.csv").read_text(encoding="utf-8") == "新的"
                    and (common.OLD_SECRETS / "gmail_candidates.csv").exists())
        inside = common.BASE in saved[0].resolve().parents
    finally:
        common.SECRETS, common.OLD_SECRETS = saved
    custom = bool(os.environ.get("PRIVACY_CHECKUP_SECRETS"))  # 自己指定位置的話，放哪裡由你決定
    ok = moved and kept and (custom or not inside)
    return ok, ("個人資料資料夾不在專案裡；舊位置的檔案會搬過去，同名的檔案不會被蓋掉" if ok
                else f"結果不對：搬過去={moved}、沒蓋掉={kept}、在專案裡={inside}")


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


def t_lookalike_stable():
    """理由太長或提到別的網站時，只拿掉理由、結論照用；判斷過的網站存起來，下次不再問 AI，報告才不會每次不一樣。"""
    import io
    from stages import ai_steps
    from stages.lookalike import build_items
    candidates = [{"id": f"L{i}", "domain": d, "host": d, "official_domain": "shopee.tw", "shop_name": "蝦皮購物",
                   "why": "網址裡有「shopee」"} for i, d in enumerate(("a.example", "b.example", "c.example"), 1)]
    asked = []

    def fake_ask(task, instructions, data, expected_type):
        asked.append(sorted(item["domain"] for item in data["lookalikes"]))
        return [{"id": "L1", "verdict": "imitation", "reason": "很像" * 25},          # 50 字，太長
                {"id": "L2", "verdict": "official", "reason": "其實是 evil.example 的分站"},  # 提到別的網站
                {"id": "L3", "verdict": "unsure", "reason": "沒把握"}]

    original = ai_steps._ask
    ai_steps._ask = fake_ask
    try:
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            cache = Path(folder) / "lookalike_verdicts.json"
            first = ai_steps.check_lookalikes(candidates[:2], cache)
            second = ai_steps.check_lookalikes(candidates, cache)  # L1、L2 沿用，只問新的 L3
            third = ai_steps.check_lookalikes(candidates, cache)   # 全部沿用，不問 AI
    finally:
        ai_steps._ask = original
    items, cleared = build_items(candidates, third)
    levels = {i["domain"]: i["default_level"] for i in items}
    ok = (first["L1"] == {"verdict": "imitation", "reason": None} and first["L2"]["reason"] is None
          and second == third and levels == {"a.example": "red", "c.example": "yellow"}
          and [c["domain"] for c in cleared] == ["b.example"] and "evil.example" not in json.dumps(cleared)
          and asked == [["a.example", "b.example"], ["c.example"]])
    return ok, ("理由沒通過檢查只拿掉理由，結論照用（仍是 🔴）；判斷過的網站下次直接沿用，只問新的" if ok
                else f"結果不對：{first}、{third}、{levels}、問了 AI：{asked}")


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


@contextlib.contextmanager
def fake_ai(reply):
    """測試用：假裝 AI 回了這段內容。用 with fake_ai(...) as sent，sent 會記下程式交給 AI 的資料。"""
    import io
    from stages import ai_steps
    sent = []

    def fake_ask(task, instructions, data, expected_type, **options):
        sent.append(data)
        return reply

    original = ai_steps._ask
    ai_steps._ask = fake_ask
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            yield sent
    finally:
        ai_steps._ask = original


def t_levels_fixed():
    """燈號由規則決定：AI 就算回傳別的等級也沒有用，只有說明文字會採用。"""
    from stages import ai_steps
    from stages.findings import finalize
    evidence = [{"id": "P1", "kind": "pwned_password", "domain": "a.com", "default_level": "red",
                 "default_reason": "規則寫的原因", "default_action": "規則寫的做法"},
                {"id": "W1", "kind": "weak_password", "domain": "b.com", "default_level": "yellow",
                 "default_reason": "規則寫的原因", "default_action": "規則寫的做法"}]
    with fake_ai([{"id": "P1", "level": "green", "reason": "其實不急", "action": "有空再到 a.com 換密碼"},
                  {"id": "W1", "level": "red", "reason": "請改到 evil.example 處理", "action": "馬上處理"}]):
        final = {f["id"]: f for f in finalize(evidence, ai_steps.explain(evidence, {"a.com", "b.com"}))}
    ok = (final["P1"]["level"] == "red" and final["P1"]["reason"] == "其實不急" and final["P1"]["ai_written"]
          and final["W1"]["level"] == "yellow" and final["W1"]["reason"] == "規則寫的原因" and not final["W1"]["ai_written"])
    return ok, ("AI 想把 🔴 降成 🟢、把 🟡 升成 🔴 都沒有用，燈號照規則；說明採用 AI 寫的，不合格的用規則寫的" if ok
                else f"結果不對：{final}")


def t_summary_numbers():
    """總結的統計數字由程式寫，也不交給 AI；AI 自己編數字的句子會被刪掉。"""
    from stages import ai_steps
    final = [{"id": "P1", "kind": "pwned_password", "level": "red", "domain": "a.com", "action": "立刻到 a.com 換密碼。"},
             {"id": "T1", "kind": "enable_2fa", "level": "green", "domain": "a.com", "action": "開啟兩步驟驗證。"}]
    counts = {"accounts": 12, "pwned_passwords": 1, "reused_groups": 1, "breaches": 3, "lookalikes": 0,
              "red": 1, "yellow": 0, "green": 1}
    with fake_ai({"summary": "你的 12 個帳號中，有 7 個狀況良好。請先到 a.com 換密碼（P1）。接到可疑電話先打 165 查證。"}) as sent:
        text, by_ai = ai_steps.summarize(final, counts, {"a.com"})
    ok = (by_ai and list(sent[0]) == ["top_findings"] and "狀況良好" not in text and "請先到 a.com 換密碼" in text
          and "打 165 查證" in text and "盤點 12 個帳號" in text and "🟢 有空再處理 1 件" in text)
    return ok, ("統計數字由程式寫、不交給 AI；AI 自己編的「7 個狀況良好」被刪掉，其他句子照常採用" if ok
                else f"結果不對：{text}、送給 AI 的欄位：{[list(d) for d in sent]}")


def t_shop_table():
    """專案內附的 165 店名對照表：沒有 AI、這台電腦也沒翻過，照樣比對得到；表上寫沒有網域的店名不會再問 AI。"""
    from stages import ai_steps
    table = json.loads(ai_steps.SHOP_TABLE.read_text(encoding="utf-8"))["shops"]
    bad = [d for entry in table.values() for d in entry["domains"] if normalize_domain(d) != d]
    empty = next(entry["shop_name"] for entry in table.values() if not entry["domains"])
    shops = [{"shop_id": "shop_1", "shop_name": "蝦皮購物", "times": 1, "last_listed": "2026-10-01"},
             {"shop_id": "shop_2", "shop_name": empty, "times": 1, "last_listed": "2026-10-01"}]
    with tempfile.TemporaryDirectory() as folder, fake_ai(None) as asked:
        matches, translated = ai_steps.match_165(shops, ["shopee.tw", "adobe.com"], Path(folder) / "shop_domains.json")
    ok = not bad and [m["domain"] for m in matches] == ["shopee.tw"] and not translated and not asked
    return ok, (f"內附 {len(table)} 個店名；不用 AI 也對得到蝦皮，表上有的店名不會再問 AI" if ok
                else f"結果不對：{matches}、格式不對的網域 {bad}、問了 AI {asked}")


def t_sent_log():
    """報告裡「這次送給 AI 的資料」：每一步送了幾次、裡面有幾個你的帳號網域，是照海關的實際紀錄算的。"""
    import llm
    from stages import report
    saved = llm.available, llm.complete
    with tempfile.TemporaryDirectory() as folder, quiet_guard(folder):
        llm.available, llm.complete = (lambda: True), (lambda system_prompt, prompt: "[]")
        try:
            guard.sent_log.clear()
            guard.ask_llm("translate_shops", "system", "說明", {"shops": [{"shop_id": "shop_1", "shop_name": "某某小舖"}]})
            guard.ask_llm("describe_sites", "system", "說明", {"sites": [{"domain": "a.com"}, {"domain": "b.com"}]})
            guard.ask_llm("explain", "system", "說明", {"evidence": [
                {"id": "B1", "domain": "a.com"}, {"id": "R1", "domain": "b.com", "domains": ["b.com", "c.com"]}]},
                hide={"網站": ["a.com", "b.com", "c.com"]})
            rows = {r["name"]: r for r in report.sent_summary(guard.sent_log, {"a.com", "b.com", "c.com", "d.com"})["rows"]}
        finally:
            llm.available, llm.complete = saved
    ok = (rows["165 店名翻成網域"]["times"] == 1 and rows["165 店名翻成網域"]["mine"] == 0
          and rows["辨認網站"]["mine"] == 2 and rows["寫白話說明"]["times"] == 1 and rows["寫白話說明"]["mine"] == 0
          and rows["寫總結"]["times"] == 0)
    return ok, ("翻店名送出 0 個你的帳號網域、辨認網站送出 2 個、寫說明用代號所以是 0 個；沒送的步驟記 0 次" if ok
                else f"結果不對：{rows}")


def t_masked_names():
    """寫說明時 AI 看到的是代號，不是網站和事件的名稱；回來之後換回原本的名稱，AI 自己編的代號不採用。"""
    import llm
    from stages import ai_steps
    evidence = [{"id": "B1", "kind": "breach", "domain": "adobe.com", "breach_name": "Adobe", "breach_date": "2013-10-04",
                 "data_classes": ["Passwords"], "first_seen": None, "default_level": "red"},
                {"id": "W1", "kind": "weak_password", "domain": "bnext.example", "default_level": "yellow"}]
    seen = []

    def fake_complete(system_prompt, prompt):
        seen.append(prompt)
        site = json.loads(prompt.split("資料（JSON）：", 1)[1])["evidence"][0]["domain"]  # AI 看到的是代號
        return json.dumps([{"id": "B1", "reason": f"{site} 在 2013-10-04 外洩過密碼", "action": f"到 {site} 換密碼"},
                           {"id": "W1", "reason": "[網站99] 的密碼太弱", "action": "換長一點的密碼"}], ensure_ascii=False)

    saved = llm.available, llm.complete
    with tempfile.TemporaryDirectory() as folder, quiet_guard(folder), contextlib.redirect_stdout(io.StringIO()):
        llm.available, llm.complete = (lambda: True), fake_complete
        try:
            overrides = ai_steps.explain(evidence, {"adobe.com", "bnext.example"})
            try:  # 忘了換代號：海關直接擋下
                guard.ask_llm("explain", "system", "說明", {"evidence": [{"id": "B1", "domain": "adobe.com"}]})
                refused = False
            except guard.Blocked:
                refused = True
        finally:
            llm.available, llm.complete = saved
    hidden = bool(seen) and not any(word in seen[0] for word in ("adobe.com", "Adobe", "bnext.example"))
    ok = (hidden and overrides == {"B1": {"reason": "adobe.com 在 2013-10-04 外洩過密碼", "action": "到 adobe.com 換密碼"}}
          and refused)
    return ok, ("送出去的內容裡沒有網域和事件名稱，只有代號；回來後換回原本的名稱；AI 編的代號不採用；沒換代號就送會被擋" if ok
                else f"結果不對：沒有露出名稱={hidden}、{overrides}、沒換代號被擋={refused}")


def t_gmail_certain_not_sent():
    """Gmail 判斷：規則已經確定還在用的網站（最近有登入、訂單信）直接填 y，不送給 AI。"""
    import datetime
    from stages import ai_steps, gmail_triage
    rows = [{"domain": "active.example", "hints": "訂單", "likely_account": "中", "first_seen": "2020-01-01",
             "last_seen": "2026-10-20", "last_activity": "2026-10-20"},
            {"domain": "quiet.example", "hints": "註冊", "likely_account": "高", "first_seen": "2018-01-01",
             "last_seen": "2021-03-01", "last_activity": ""}]
    asked = []
    original = ai_steps.classify_senders
    ai_steps.classify_senders = lambda todo, today: asked.extend(r["domain"] for r in todo) or {}
    saved = llm_state()
    try:
        with contextlib.redirect_stdout(io.StringIO()), tempfile.TemporaryDirectory() as folder, quiet_guard(folder):
            import llm
            llm.configure = lambda backend, model=None: None
            llm.available = lambda: True
            llm.describe = lambda: "測試"
            gmail_triage.run(rows, "auto", today=datetime.date(2026, 11, 10))
    finally:
        ai_steps.classify_senders = original
        saved()
    ok = asked == ["quiet.example"] and rows[0]["still_using"] == "y" and not rows[0]["review"]
    return ok, "最近有訂單信的網站直接填 y、沒有送給 AI；看不出來的才送" if ok else f"結果不對：送給 AI {asked}、{rows[0]}"


def llm_state():
    """測試用：記下 llm 模組現在的狀態，回傳一個可以把它還原的函式。"""
    import llm
    names = ["configure", "available", "describe", "complete"]
    saved = {name: getattr(llm, name) for name in names}
    return lambda: [setattr(llm, name, value) for name, value in saved.items()]


def _two_findings(order):
    """兩個網站各有一起外洩事件，其中 a.com 的密碼也出現在外洩密碼庫。order 決定帳號的順序。"""
    from stages.findings import assign_keys, build_evidence
    accounts = [{"domain": d, "sources": [], "still_using": True, "first_seen": None} for d in order]
    breaches = [{"domain": d, "breach_name": d.upper(), "breach_date": "2019-01-01", "data_classes": ["Passwords"],
                 "pwn_count": 1, "verified": True} for d in order]
    pw = [{"domain": "a.com", "host": "a.com", "pwned_count": 9, "reused": False, "reuse_group": None,
           "strength": 0, "strength_label": "很弱"}]
    return assign_keys(build_evidence(pw, accounts, breaches, [], []))


def t_compare_runs():
    """和上次比：用不會變的編號比對，所以帳號順序變了也認得出是同一個問題。"""
    from stages import history
    from stages.findings import finalize
    first, second = _two_findings(["a.com", "b.com"]), _two_findings(["b.com", "a.com"])
    ids = {e["key"]: e["id"] for e in first}, {e["key"]: e["id"] for e in second}
    stable = set(ids[0]) == set(ids[1]) and ids[0] != ids[1]  # 流水號變了，key 沒變
    before = [{k: f[k] for k in ("key", "title", "kind", "domain", "level")} for f in finalize(first, {})]
    # 第二次：a.com 換了密碼（P 不見了）、你把 b.com 的外洩事件標記已處理、多了一個弱密碼
    now = [e for e in second if e["kind"] != "pwned_password"]
    now.append({"id": "W1", "kind": "weak_password", "domain": "c.com", "default_level": "yellow",
                "default_reason": "", "default_action": "", "key": "weak_password|c.com", "title": "c.com：密碼太弱"})
    done = {"breach|b.com|B.COM": {"date": "2026-11-10", "title": "b.com"}}
    diff = history.compare(before, finalize(now, {}, done))
    got = {name: [i["key"] for i in diff[name]] for name in ("resolved", "marked", "new")}
    ok = (stable and got == {"resolved": ["pwned_password|a.com"], "marked": ["breach|b.com|B.COM"],
                             "new": ["weak_password|c.com"]} and diff["still"] == {"red": 1})
    return ok, ("帳號順序變了流水號會變、比對用的編號不變；解決的、你標記的、新出現的、還沒處理的都分得出來" if ok
                else f"結果不對：編號不變={stable}、{got}、{diff['still']}")


def t_mark_done():
    """標記已處理：外洩事件可以標，密碼的問題不能標（要重新檢查才算數）；標記後不列入燈號，也可以取消。"""
    from stages import history
    from stages.findings import finalize
    evidence = _two_findings(["a.com", "b.com"])
    with tempfile.TemporaryDirectory() as folder:
        out_dir = Path(folder)
        save_json(out_dir / "final.json", finalize(evidence, {}))
        messages = history.mark(out_dir, ["b1", "P1", "X9"])
        marked = history.load_done(out_dir)
        levels = {f["id"]: f["level"] for f in finalize(evidence, {}, marked)}
        history.mark(out_dir, ["B1"], undo=True)
        after_undo = history.load_done(out_dir)
    ok = (list(marked) == ["breach|a.com|A.COM"] and levels == {"P1": "red", "B1": "done", "B2": "red"}
          and len(messages) == 3 and not after_undo)
    return ok, ("外洩事件標記後不列入燈號；密碼的問題和不存在的編號不能標；取消標記後恢復原狀" if ok
                else f"結果不對：{marked}、{levels}、{messages}、{after_undo}")


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


def t_auto_pick():
    """模擬幾種電腦：只裝了一種、裝了但沒登入、登入了但呼叫失敗，auto 都要選到能用的那一個。"""
    import io
    import llm
    patched = ["find_claude", "find_codex", "gemini_api_key", "_claude_logged_in", "_codex_logged_in",
               "_codex_features_to_disable", "_claude", "_codex"]
    state = ["_backend", "_auto", "_binary", "_model", "_api_key", "_codex_disabled", "_candidates", "_verified"]
    saved = {name: getattr(llm, name) for name in patched + state}  # main.py 已經選好 AI 了，測完要還原

    def computer(claude=None, codex=None, fail=()):
        """claude / codex：None 沒裝、"out" 裝了沒登入、"in" 登入了。fail：呼叫會失敗的 AI。"""
        llm.find_claude = lambda: "claude" if claude else None
        llm.find_codex = lambda: "codex" if codex else None
        llm.gemini_api_key = lambda: None
        llm._claude_logged_in = lambda binary: claude == "in"
        llm._codex_logged_in = lambda binary: codex == "in"
        llm._codex_features_to_disable = lambda: []

        def answer(name):
            def call(system_prompt, prompt, server=None):
                if name in fail:
                    raise RuntimeError("額度用完")
                return name
            return call
        llm._claude, llm._codex = answer("claude"), answer("codex")
        llm.configure("auto")
        if not llm.available():
            return "none", None
        try:
            reply = llm.complete("system", "prompt")
        except RuntimeError:
            reply = None
        return llm._backend, reply  # 呼叫完再看用的是哪一個（中途可能換過）

    try:
        with contextlib.redirect_stdout(io.StringIO()):
            cases = {
                "只裝 Claude": (computer(claude="in"), ("claude", "claude")),
                "只裝 Codex": (computer(codex="in"), ("codex", "codex")),
                "Claude 沒登入 → Codex": (computer(claude="out", codex="in"), ("codex", "codex")),
                "Claude 呼叫失敗 → Codex": (computer(claude="in", codex="in", fail={"claude"}), ("codex", "codex")),
                "都沒登入 → 不用 AI": (computer(claude="out", codex="out"), ("none", None)),
            }
            # 成功過一次之後就固定用它：之後失敗不會換 AI，交給呼叫的人改用規則判斷
            computer(claude="in", codex="in")

            def timeout(*args, **kwargs):
                raise RuntimeError("逾時")
            llm._claude = timeout
            try:
                llm.complete("system", "prompt")
                stays = False
            except RuntimeError:
                stays = llm._backend == "claude"
    finally:
        for name, value in saved.items():
            setattr(llm, name, value)
    wrong = [name for name, (got, expected) in cases.items() if got != expected]
    ok = not wrong and stays
    return ok, ("裝了沒登入、呼叫失敗都會自動換下一個；成功過之後就固定用同一個" if ok
                else f"結果不對：{wrong or '成功過之後還是換了 AI'}")


TESTS = [
    ("網址整理", t_domains),
    ("白名單：每個工作各一份", t_whitelist),
    ("主程式不載入實驗功能", t_core_only),
    ("海關：身分證字號", blocks("A123456789", "身分證字號")),
    ("海關：信用卡號", blocks("4111 1111 1111 1111", "測試用信用卡號")),
    ("海關：email", blocks("demo@example.com", " email")),
    ("海關：手機號碼", blocks("0912-345-678", "手機號碼")),
    ("海關：你的密碼", t_blocks_my_password),
    ("海關：特殊字元的密碼", t_blocks_odd_passwords),
    ("海關：不誤擋", t_clean_passes),
    ("個人資料放在專案外", t_secrets_outside),
    ("Gmail 寄件者整理", t_gmail_aggregate),
    ("日期格式", t_dates),
    ("下載快取", t_download_cache),
    ("外洩前後判斷", t_breach_timing),
    ("連鎖風險", t_chain_risk),
    ("165 公告解析", t_165_parse),
    ("外洩事件比對", t_adobe_breach),
    ("外洩密碼：已知外洩", t_known_pwned),
    ("外洩密碼：不誤判", t_random_not_pwned),
    ("165 比對在本機", t_165_local_match),
    ("165 店名對照表（內附）", t_shop_table),
    ("仿冒網域：抓得到、不誤報", t_lookalike_candidates),
    ("仿冒網域：燈號", t_lookalike_levels),
    ("仿冒網域：結果穩定", t_lookalike_stable),
    ("寄件者名稱整理", t_sender_names),
    ("Gmail 自動判斷", t_gmail_triage),
    ("保留你填的答案", t_keep_user_answers),
    ("AI 回覆檢查：寄件者、網站說明", t_ai_reply_checks),
    ("AI 文字檢查：網址", t_text_check),
    ("燈號由規則決定", t_levels_fixed),
    ("總結：數字由程式寫", t_summary_numbers),
    ("送給 AI 的紀錄", t_sent_log),
    ("代號：寫說明時不送網站名稱", t_masked_names),
    ("Gmail：規則確定的不送給 AI", t_gmail_certain_not_sent),
    ("和上次比", t_compare_runs),
    ("和上次比：沒檢查密碼的時候", t_without_passwords),
    ("標記已處理", t_mark_done),
    ("密碼檔：只認匯出檔", t_export_detect),
    ("密碼檔：等你匯出、讀完就刪", t_wait_and_destroy),
    ("密碼檔：雲端同步資料夾", t_sync_folder),
    ("Codex 違規偵測", t_codex_violations),
    ("自動選擇 AI（模擬）", t_auto_pick),
]


def run_all(include_experimental=False):
    """include_experimental：實驗功能（experimental/）的測試也一起跑。主程式只有加 --agent 時才會跑它們。"""
    tests = list(TESTS)
    if include_experimental:
        from experimental.tests import TESTS as experimental_tests
        tests += experimental_tests
    results = []
    for name, test in tests:
        try:
            ok, detail = test()
        except Exception as error:
            ok, detail = False, f"發生錯誤：{error}"
        results.append((name, ok, detail))
    return results


if __name__ == "__main__":
    sys.stdout.reconfigure(errors="replace")
    from tests import known_answers  # 用正式的模組名稱載入，實驗功能的測試才會用到同一份
    results = known_answers.run_all(include_experimental=True)  # 單獨執行時，實驗功能的測試也一起跑
    for name, ok, detail in results:
        print(f"[{'通過' if ok else '失敗'}] {name}：{detail}")
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)
