"""Gmail 寄件者掃描：找出所有寄過信給你的網站，產生帳號候選清單。

- 只申請 gmail.metadata 權限：只能讀信件標頭（寄件者、主旨、日期），
  Google 不會讓這個程式讀到信件內容和附件
- 全部在你的電腦上處理；主旨只拿來判斷是不是註冊信、訂單信，不會寫進檔案，也不會交給 AI
- 輸出 secrets/gmail_candidates.csv。AI 和規則都同意的，會自動在 still_using 填 y（還在用）或 n（不用了）；
  意見不同或沒把握的標 ★，排在最前面讓你確認（見 stages/gmail_triage.py）
- 掃完會問你要不要撤銷這次的授權（建議撤銷，用完就收回權限）

用法：
  python gmail_scan.py                            # 掃描整個信箱
  python gmail_scan.py --limit 500                # 只掃最新的 500 封，先試試看
  python gmail_scan.py --profile demo --no-browser  # 示範帳號：檔案分開存，登入網址自己貼到示範用的瀏覽器
  python gmail_scan.py --retriage                 # 不重新掃描，用現有的候選清單重新判斷
"""
import argparse
import csv
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from email.header import decode_header, make_header
from email.utils import parseaddr

import llm
from common import BASE, normalize_domain, read_csv_rows
from stages import gmail_triage

SECRETS = BASE / "secrets"
CREDENTIALS = SECRETS / "gmail_credentials.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.metadata"]
BATCH_SIZE = 50   # Google 建議一批不要超過 50 個請求
PAUSE = 1.2       # 每批之間休息一下，避免超過每秒的用量上限

# 個人信箱（朋友寄的信），不是網站帳號
PERSONAL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.com.tw", "hotmail.com", "hotmail.com.tw",
    "outlook.com", "live.com", "msn.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "qq.com", "163.com", "126.com",
}
# 第三方寄信平台：寄件者網域是平台，不是實際的網站，要看寄件者名稱判斷
SENDING_PLATFORMS = {
    "mailchimpapp.com", "mcsv.net", "sendgrid.net", "amazonses.com", "mailgun.org", "sparkpostmail.com",
    "substack.com", "beehiiv.com", "convertkit.com", "hubspotemail.net", "brevo.com", "sendinblue.com",
    "mailerlite.com", "ccsend.com", "constantcontact.com", "intercom-mail.com", "zendesk.com",
    "freshdesk.com", "surveycake.com",
}
HINTS = {
    "安全通知": ["密碼", "登入", "安全性", "password", "sign-in", "sign in", "login", "log in", "security", "2-step"],
    "註冊": ["歡迎", "註冊", "驗證", "啟用", "確認您的", "開通", "welcome", "verify", "confirm", "activate", "sign up"],
    "訂單": ["訂單", "付款", "收據", "出貨", "發票", "繳費", "order", "receipt", "invoice", "payment", "shipped"],
}
LIKELY_ORDER = {"高": 0, "中": 1, "低": 2}
COLUMNS = ["domain", "still_using", "review", "suggested", "reason", "site_info", "is_account", "note",
           "emails", "first_seen", "last_seen", "last_activity", "hints", "likely_account", "sender_name",
           "platform_note"]

SETUP_HELP = f"""\
找不到 Google 憑證檔：{CREDENTIALS}

第一次使用要先在 Google Cloud 設定（約 15～20 分鐘，只要做一次），步驟見 README.md 的「Gmail 寄件者掃描」。
完成後把下載的 JSON 檔改名成 gmail_credentials.json，放進 secrets/ 資料夾。"""


def profile_paths(profile):
    """不同帳號（例如你自己的、示範用的）的登入憑證和候選清單分開存，不會混在一起。"""
    suffix = f"_{profile}" if profile else ""
    return SECRETS / f"gmail_token{suffix}.json", SECRETS / f"gmail_candidates{suffix}.csv"


def _decode(value):
    """處理 =?UTF-8?B?...?= 這類編碼過的標頭；已經是一般文字的就原樣回傳。"""
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        return value or ""


def aggregate(messages):
    """把每封信的標頭整理成「每個網站一列」。messages 的每一筆：
    {"from": 寄件者, "subject": 主旨, "date_ms": 收信時間, "unsubscribe": 是否有取消訂閱標頭}"""
    stats = {}
    for m in messages:
        name, address = parseaddr(_decode(m["from"]))
        domain = normalize_domain(address.rpartition("@")[2]) if "@" in address else None
        if not domain or domain in PERSONAL_DOMAINS:
            continue
        s = stats.setdefault(domain, {"count": 0, "first": m["date_ms"], "last": m["date_ms"], "activity": None,
                                      "hints": set(), "names": Counter()})
        s["count"] += 1
        s["first"], s["last"] = min(s["first"], m["date_ms"]), max(s["last"], m["date_ms"])
        subject = _decode(m["subject"]).lower()
        for label, words in HINTS.items():
            if any(word in subject for word in words):
                s["hints"].add(label)
                if label in ("安全通知", "訂單"):  # 登入通知、訂單代表你真的有在用這個帳號
                    s["activity"] = max(s["activity"] or 0, m["date_ms"])
        if m["unsubscribe"]:
            s["hints"].add("電子報")
        if name:
            s["names"][name.strip()] += 1

    def day(ms):
        return time.strftime("%Y-%m-%d", time.localtime(ms / 1000)) if ms else ""

    rows = []
    for domain, s in stats.items():
        likely = "高" if s["hints"] & {"註冊", "安全通知"} else "中" if "訂單" in s["hints"] else "低"
        rows.append({
            "domain": domain, "still_using": "", "review": "", "suggested": "", "reason": "",
            "site_info": "", "is_account": "", "note": "",
            "likely_account": likely,
            "emails": s["count"],
            "first_seen": day(s["first"]),
            "last_seen": day(s["last"]),
            "last_activity": day(s["activity"]),
            "hints": "、".join(h for h in ("安全通知", "註冊", "訂單", "電子報") if h in s["hints"]),
            "sender_name": s["names"].most_common(1)[0][0] if s["names"] else "",
            "platform_note": "寄信平台，實際網站請看 sender_name" if domain in SENDING_PLATFORMS else "",
        })
    rows.sort(key=lambda r: (LIKELY_ORDER[r["likely_account"]], -r["emails"]))
    return rows


def get_service(token_path, open_browser=True):
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError:
        sys.exit("需要先安裝 Google 官方套件：\n  pip install google-api-python-client google-auth-oauthlib")
    if not CREDENTIALS.exists():
        sys.exit(SETUP_HELP)

    creds = Credentials.from_authorized_user_file(str(token_path), SCOPES) if token_path.exists() else None
    if creds and not creds.valid and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except Exception:
            creds = None
    if not creds or not creds.valid:
        if open_browser:
            print("  瀏覽器會開啟 Google 登入頁面。")
        else:
            print("  請把下面的網址複製到「示範用的瀏覽器視窗」打開，登入示範帳號。")
        print("  看到「Google 尚未驗證這個應用程式」是正常的（這是你自己建的），按「繼續」即可。")
        print("  權限頁面應該只寫「查看您的電子郵件訊息中繼資料，例如標籤和標頭，但不包括電子郵件內文」。")
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS), SCOPES)
        # select_account：每次都讓你選帳號，避免不小心用錯帳號登入
        creds = flow.run_local_server(port=0, prompt="consent select_account", open_browser=open_browser)
        token_path.write_text(creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds, cache_discovery=False), creds


def fetch_messages(service, limit=None):
    ids = []
    request = service.users().messages().list(userId="me", maxResults=500)
    while request is not None:
        response = request.execute()
        ids += [m["id"] for m in response.get("messages", [])]
        print(f"\r  找到 {len(ids):,} 封信…", end="", flush=True)
        if limit and len(ids) >= limit:
            ids = ids[:limit]
            break
        request = service.users().messages().list_next(request, response)
    print(f"\r  共 {len(ids):,} 封信，開始讀取寄件者（大約每秒 40 封）")

    messages, failed = [], []

    def on_response(message_id, response, error):
        if error:
            failed.append(message_id)
            return
        headers = {h["name"].lower(): h["value"] for h in response.get("payload", {}).get("headers", [])}
        messages.append({"from": headers.get("from", ""), "subject": headers.get("subject", ""),
                         "date_ms": int(response.get("internalDate", 0)),
                         "unsubscribe": "list-unsubscribe" in headers})

    pending = ids
    for attempt in range(6):
        failed.clear()
        for start in range(0, len(pending), BATCH_SIZE):
            batch = service.new_batch_http_request(callback=on_response)
            for message_id in pending[start:start + BATCH_SIZE]:
                batch.add(service.users().messages().get(
                    userId="me", id=message_id, format="metadata",
                    metadataHeaders=["From", "Subject", "List-Unsubscribe"]), request_id=message_id)
            batch.execute()
            print(f"\r  已讀取 {len(messages):,} / {len(ids):,}", end="", flush=True)
            time.sleep(PAUSE)
        if not failed:
            break
        pending = list(failed)
        print(f"\n  有 {len(pending)} 封被 Google 暫時拒絕（用量上限），等 {2 ** attempt} 秒後重試…")
        time.sleep(2 ** attempt)
    print()
    if failed:
        print(f"  [注意] 有 {len(failed)} 封重試後仍然讀不到，已略過")
    return messages


def carry_over(row, old):
    """沿用上次的 note；still_using 只沿用「你自己填的」。
    上次自動填、你也沒改過的答案（還等於 suggested）不沿用，這次用新的信件重新判斷。"""
    row["note"] = old.get("note") or ""
    answer = (old.get("still_using") or "").strip()
    auto = bool(old.get("suggested")) and answer == old.get("suggested") and not old.get("review")
    if answer and not auto:
        row["still_using"], row["decided_by_you"] = answer, True
        row["site_info"], row["is_account"] = old.get("site_info") or "", old.get("is_account") or ""


def keep_previous_answers(rows, output):
    """重新掃描時，保留你上次填過的內容。"""
    if not output.exists():
        return rows
    previous = {r.get("domain"): r for r in read_csv_rows(output)}
    for row in rows:
        old = previous.get(row["domain"])
        if old:
            carry_over(row, old)
    return rows


def load_for_retriage(output):
    """不重新掃描：讀現有的候選清單，清掉上次自動填的答案，保留你填的。"""
    if not output.exists():
        sys.exit(f"找不到候選清單：{output}，請先執行一次掃描。")
    rows = []
    for old in read_csv_rows(output):
        row = {column: old.get(column) or "" for column in COLUMNS}
        row["still_using"] = ""
        carry_over(row, old)
        rows.append(row)
    return rows


def sort_key(row):
    """要你確認的排最前面，接著是自動判斷的帳號，不是帳號的放最後。"""
    group = 0 if row.get("review") else 1 if row.get("still_using") else 2
    return group, LIKELY_ORDER.get(row.get("likely_account"), 2), -int(row.get("emails") or 0)


def print_summary(rows, stats, without_ai, used_ai, output):
    print(f"\n{len(rows)} 個寄過信給你的網站：")
    print(f"  自動判斷：還在用 {stats['還在用']} 個、不用了 {stats['不用了']} 個、不是帳號 {stats['不是帳號']} 個"
          + ("（AI＋規則都同意才自動填）" if used_ai else "（只用規則）"))
    if stats["你填的"]:
        print(f"  你之前填過的：{stats['你填的']} 個（保留不動）")
    print(f"  ★ 要你確認：{stats['要你確認']} 個（已經排在最前面）")
    if used_ai:
        print(f"  （沒有 AI 的話，要你確認的會是 {without_ai} 個）")
    print(f"候選清單：{output}")
    print("下一步：打開它，只要看標 ★ 的列：參考 suggested 和 reason，在 still_using 填 y 或 n。")
    print("        自動填的答案不對也可以直接改，下次重新掃描會保留你改的。")


def revoke(creds, token_path):
    data = urllib.parse.urlencode({"token": creds.refresh_token or creds.token}).encode()
    request = urllib.request.Request("https://oauth2.googleapis.com/revoke", data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        urllib.request.urlopen(request, timeout=30)
        print("  已撤銷授權。這個程式現在無法再讀取這個 Gmail。")
    except OSError as error:
        print(f"  [注意] 撤銷失敗（{error}），請到 https://myaccount.google.com/connections 手動移除")
    token_path.unlink(missing_ok=True)


def main():
    sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="掃描 Gmail 寄件者，產生帳號候選清單")
    parser.add_argument("--limit", type=int, help="只掃描最新的 N 封信（先試試看用）")
    parser.add_argument("--profile", help="帳號代號，例如 demo；不同代號的檔案分開存")
    parser.add_argument("--no-browser", action="store_true", help="不自動開瀏覽器，改成印出登入網址")
    parser.add_argument("--llm", choices=llm.CHOICES, default="auto",
                        help="幫忙判斷的 AI（預設 auto：自動找電腦上有的 claude → codex → gemini）；"
                             "none = 只用規則，要你確認的會比較多")
    parser.add_argument("--model", help="指定 AI 模型")
    parser.add_argument("--retriage", action="store_true", help="不重新掃描 Gmail，用現有的候選清單重新判斷")
    args = parser.parse_args()
    token_path, output = profile_paths(args.profile)

    print("=== Gmail 寄件者掃描（只讀信件標頭，不讀內容） ===")
    if args.profile:
        print(f"帳號代號：{args.profile}（結果存在 {output.name}）")
    creds = None
    if args.retriage:
        print("不重新掃描，用現有的候選清單重新判斷")
        rows = load_for_retriage(output)
    else:
        service, creds = get_service(token_path, open_browser=not args.no_browser)
        rows = keep_previous_answers(aggregate(fetch_messages(service, args.limit)), output)

    stats, without_ai, used_ai = gmail_triage.run(rows, args.llm, args.model)
    rows.sort(key=sort_key)
    SECRETS.mkdir(exist_ok=True)
    with open(output, "w", newline="", encoding="utf-8-sig") as f:  # 加 BOM，用 Excel 打開中文才不會亂碼
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print_summary(rows, stats, without_ai, used_ai, output)
    if creds is None:
        return

    try:
        answer = input("\n要撤銷這次的 Gmail 授權嗎？（建議撤銷，之後要重掃再登入一次就好）(Y/n) ").strip().lower()
    except EOFError:
        answer = ""
    if answer in ("", "y", "yes", "是"):
        revoke(creds, token_path)


if __name__ == "__main__":
    main()
