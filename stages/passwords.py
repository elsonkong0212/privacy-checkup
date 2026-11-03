"""M2 密碼檢查（純程式，不經過 AI）。

讀取瀏覽器或密碼管理器匯出的 CSV，對每組密碼：
- 查有沒有出現在外洩密碼庫（只送出雜湊值的前 5 個字元給 HIBP）
- 找出重複使用的密碼
- 估計強度
輸出的摘要裡只有網域和結果，沒有密碼，也沒有帳號名稱。
"""
import csv
import hashlib
import string
from collections import Counter

from common import hostname, http_get, normalize_domain

URL_COLUMNS = ("url", "login_uri", "website")              # Chrome/Edge、Firefox、Bitwarden
PASSWORD_COLUMNS = ("password", "login_password")
RANGE_API = "https://api.pwnedpasswords.com/range/"
STRENGTH_LABELS = ["很弱", "弱", "普通", "強", "很強"]


def sha1_hex(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def pwned_count(sha1, cache):
    """回傳這個雜湊值在外洩密碼庫裡出現的次數。只有前 5 碼會離開這台電腦。"""
    prefix, suffix = sha1[:5], sha1[5:]
    if prefix not in cache:
        # Add-Padding：HIBP 會在回應裡混入假資料，連「回應大小」都看不出你查了什麼
        body = http_get(RANGE_API + prefix, headers={"Add-Padding": "true"}).decode("utf-8")
        cache[prefix] = {}
        for line in body.splitlines():
            hash_suffix, _, count = line.partition(":")
            if count.strip() not in ("", "0"):
                cache[prefix][hash_suffix] = int(count)
    return cache[prefix].get(suffix, 0)


def estimate_strength(password):
    """0（很弱）～ 4（很強）。有安裝 zxcvbn 就用它，沒有就用長度和字元種類估計。"""
    try:
        from zxcvbn import zxcvbn
        return zxcvbn(password)["score"]
    except ImportError:
        pass
    kinds = sum(any(ch in group for ch in password)
                for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits))
    kinds += any(not ch.isalnum() for ch in password)
    length = len(password)
    if length < 8:
        return 0
    if length < 10:
        return 1 if kinds < 3 else 2
    if length < 14:
        return 2 if kinds < 3 else 3
    return 3 if kinds < 2 else 4


def read_password_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        columns = {c.strip().lower(): c for c in reader.fieldnames or []}
        url_col = next((columns[c] for c in URL_COLUMNS if c in columns), None)
        pw_col = next((columns[c] for c in PASSWORD_COLUMNS if c in columns), None)
        if not url_col or not pw_col:
            raise SystemExit(f"看不懂這個 CSV 的欄位：{reader.fieldnames}\n"
                             "目前支援 Chrome、Edge、Firefox、Bitwarden 的匯出格式。")
        for row in reader:
            yield row.get(url_col) or "", row.get(pw_col) or ""


def run(csv_path):
    """回傳 (摘要, 密碼雜湊值集合, 略過的筆數)。雜湊值只留在記憶體，給海關比對用。"""
    entries = []
    skipped = 0
    for url, password in read_password_csv(csv_path):
        domain = normalize_domain(url)
        if not domain or not password:
            skipped += 1
            continue
        entries.append((domain, hostname(url) or domain, sha1_hex(password), estimate_strength(password)))

    # 之後只用雜湊值判斷「有沒有外洩」和「有沒有重複」
    reuse = Counter(h for _, _, h, _ in entries)
    group_ids = {}
    for _, _, h, _ in entries:
        if reuse[h] > 1 and h not in group_ids:
            group_ids[h] = len(group_ids) + 1

    cache = {}
    summary = []
    for domain, host, h, strength in entries:
        count = pwned_count(h, cache)
        strength = 0 if count else strength  # 外洩過的密碼再長也不安全
        summary.append({
            "domain": domain,
            "host": host,  # 完整網址，報告裡用來分辨同一個網站底下的不同系統（不會交給 AI）
            "pwned_count": count,
            "reused": reuse[h] > 1,
            "reuse_group": group_ids.get(h),
            "strength": strength,
            "strength_label": STRENGTH_LABELS[strength],
        })
    return summary, {h for _, _, h, _ in entries}, skipped
