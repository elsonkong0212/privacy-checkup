"""M1 帳號盤點：把不同來源找到的帳號合併成一份清單。

來源：
- 密碼管理器匯出的網址（M2 已經整理好）
- Gmail 寄件者掃描 gmail_candidates.csv（填了答案的，以及標 ★ 待確認的帳號）
- 手動清單 my_accounts.csv（從 Google/Facebook 登入紀錄整理出來的）
- holehe（選用，只能查自己的 email）
"""
import re
import shutil
import subprocess
from pathlib import Path

from common import normalize_domain, parse_date, read_csv_rows


def load_manual(path, require_answer=False):
    """still_using：y、n，或 ?（有帳號，但不知道是什麼網站，報告會請 AI 辨認）。

    require_answer=True 時（Gmail 候選清單），只收填了答案的列，以及標 ★ 待確認、或 AI 判斷是帳號的列；
    待確認的帳號在你回答之前，照樣納入健檢，只是不知道還有沒有在用。"""
    if not path or not Path(path).exists():
        return []
    rows = []
    for row in read_csv_rows(path):
        domain = normalize_domain(row.get("domain", ""))
        if not domain:
            continue
        flag = (row.get("still_using") or "").strip().lower()
        still_using = True if flag in ("y", "yes", "是") else False if flag in ("n", "no", "否") else None
        unknown = flag in ("?", "？")
        if require_answer and still_using is None and not unknown \
                and not row.get("review") and row.get("is_account") != "帳號":
            continue
        rows.append({"domain": domain, "still_using": still_using, "unknown": unknown,
                     "first_seen": parse_date(row.get("first_seen")),
                     "sender_name": (row.get("sender_name") or "").strip(),
                     "site_info": (row.get("site_info") or "").strip()})
    return rows


def run_holehe(email):
    executable = shutil.which("holehe")
    if not executable:
        print("  [注意] 沒有安裝 holehe（pip install holehe），略過這一步")
        return []
    print("  執行 holehe 中，大約需要 1～2 分鐘…")
    result = subprocess.run([executable, email, "--only-used", "--no-color", "--no-clear"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    found = re.findall(r"\[\+\]\s+(\S+)", result.stdout)
    return sorted({d for d in (normalize_domain(x) for x in found) if d})


def run(password_summary, manual_path=None, email=None, use_holehe=False, gmail_path=None):
    accounts = {}

    def add(domain, source, still_using=None, first_seen=None, unknown=False, sender_name="", site_info=""):
        account = accounts.setdefault(domain, {"domain": domain, "sources": [], "still_using": None,
                                               "first_seen": None, "unknown": False})
        if source not in account["sources"]:
            account["sources"].append(source)
        if still_using is not None:
            account["still_using"] = still_using
        if first_seen and (not account["first_seen"] or first_seen < account["first_seen"]):
            account["first_seen"] = first_seen  # 最早收到這個網站來信的日期，大約等於註冊時間
        account["unknown"] = account["unknown"] or unknown
        # 寄件者名稱、Gmail 掃描時 AI 寫的網站說明：辨認網站時參考用，只存在你的電腦上
        if sender_name and not account.get("sender_name"):
            account["sender_name"] = sender_name
        if site_info and site_info != "不確定" and not account.get("site_info"):
            account["site_info"] = site_info

    for item in password_summary:
        add(item["domain"], "密碼管理器")
    for row in load_manual(gmail_path, require_answer=True):
        add(row["domain"], "Gmail", row["still_using"], row["first_seen"], row["unknown"],
            row["sender_name"], row["site_info"])
    for row in load_manual(manual_path):  # 手動清單最後讀，填的內容優先
        add(row["domain"], "手動清單", row["still_using"], unknown=row["unknown"])
    if use_holehe and email:
        for domain in run_holehe(email):
            add(domain, "holehe")
    return sorted(accounts.values(), key=lambda a: a["domain"])
