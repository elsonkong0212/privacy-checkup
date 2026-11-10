"""M2 密碼檢查（純程式，不經過 AI）。

讀取瀏覽器或密碼管理器匯出的 CSV，對每組密碼：
- 查有沒有出現在外洩密碼庫（只送出雜湊值的前 5 個字元給 HIBP）
- 找出重複使用的密碼
- 估計強度
輸出的摘要裡只有網域和結果，沒有密碼，也沒有帳號名稱。

明文密碼檔是整個流程最危險的東西，所以盡量縮短它留在硬碟上的時間：
- 程式先等你匯出（wait_for_export），檔案一出現就讀取
- 讀檔時每組密碼馬上換成雜湊值（read_entries），讀完就刪檔（destroy）；之後查外洩、找重複只用雜湊值（check）
- 每次執行都會找出以前留下的匯出檔（find_exports），並提醒會自動同步到雲端的資料夾（sync_service）
"""
import csv
import hashlib
import os
import string
import time
from collections import Counter
from pathlib import Path

from common import hostname, http_get, normalize_domain

URL_COLUMNS = ("url", "login_uri", "website")              # Chrome/Edge、Firefox、Bitwarden
PASSWORD_COLUMNS = ("password", "login_password")
RANGE_API = "https://api.pwnedpasswords.com/range/"
STRENGTH_LABELS = ["很弱", "弱", "普通", "強", "很強"]
# 資料夾名稱開頭是這些字的，通常會自動同步到雲端（例如「OneDrive - 國立成功大學」）
SYNC_FOLDERS = {"onedrive": "OneDrive", "dropbox": "Dropbox", "google drive": "Google 雲端硬碟",
                "googledrive": "Google 雲端硬碟", "我的雲端硬碟": "Google 雲端硬碟", "my drive": "Google 雲端硬碟",
                "icloud": "iCloud", "mobile documents": "iCloud", "cloudstorage": "雲端硬碟"}


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


def looks_like_export(path):
    """只看第一行的欄位名稱，判斷是不是瀏覽器或密碼管理器匯出的密碼檔（不會讀到密碼）。"""
    try:
        with open(path, encoding="utf-8-sig", errors="ignore") as f:
            header = next(csv.reader([f.readline()]), [])
    except OSError:
        return False
    columns = {c.strip().lower() for c in header}
    return bool(columns & set(URL_COLUMNS)) and bool(columns & set(PASSWORD_COLUMNS))


def find_exports(folders, newer_than=0.0):
    """這些資料夾裡（不含子資料夾）看起來像密碼匯出檔的 CSV，只算 newer_than 之後寫入的。"""
    found = []
    for folder in map(Path, folders):
        for path in sorted(folder.glob("*.csv")) if folder.is_dir() else []:
            try:
                if path.stat().st_mtime >= newer_than and looks_like_export(path):
                    found.append(path)
            except OSError:
                continue  # 剛好被刪掉
    return found


def _stamp(path):
    stat = path.stat()
    return stat.st_mtime_ns, stat.st_size


def snapshot(folders):
    """開始等之前，這些資料夾裡已經有哪些密碼檔（和它們的修改時間、大小）。"""
    stamps = {}
    for path in find_exports(folders):
        try:
            stamps[path] = _stamp(path)
        except OSError:
            continue
    return stamps


def wait_for_export(folders, before, timeout=600, interval=0.25):
    """等你匯出密碼：回傳 before（snapshot 的結果）裡沒有、或內容變了的密碼檔，而且要已經寫完
    （連續兩次檢查大小都沒變）；逾時回傳 None。
    不用「修改時間」判斷新舊：在檔案總管複製貼上或搬移的檔案會保留原本的修改時間，會被誤認成舊檔。"""
    sizes = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        for path in find_exports(folders):
            try:
                stamp = _stamp(path)
            except OSError:
                continue
            if before.get(path) == stamp:
                continue  # 開始等之前就在了，而且沒有變
            size = stamp[1]
            if size and sizes.get(path) == size:
                return path
            sizes[path] = size
        time.sleep(interval)
    return None


def sync_service(folder):
    """這個資料夾會自動同步到雲端嗎？回傳服務名稱（例如 OneDrive），不會就回傳 None。"""
    path = Path(os.path.abspath(folder))
    for key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):  # Windows 會設定這些環境變數
        root = os.environ.get(key)
        if root and path.is_relative_to(os.path.abspath(root)):
            return "OneDrive"
    for part in path.parts:
        for prefix, service in SYNC_FOLDERS.items():
            if part.lower().startswith(prefix):
                return service
    return None


def destroy(path):
    """刪掉明文密碼檔：先用 0 蓋掉內容再刪除，不經過資源回收筒。
    SSD 不保證蓋得掉舊資料，所以真正的重點是「讓它只存在幾秒」；更完整的保護是整顆硬碟加密
    （Windows 的 BitLocker、Mac 的 FileVault）。"""
    path = Path(path)
    try:
        with open(path, "r+b") as f:
            f.write(b"\0" * path.stat().st_size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass  # 蓋不掉也要繼續刪
    path.unlink()


def read_entries(csv_path):
    """讀密碼檔，每組密碼馬上換成雜湊值。讀完就可以刪檔，密碼本身不會留下來。

    回傳 ([(網域, 完整網址, 雜湊值, 強度)], {密碼雜湊值: 密碼長度}, 略過的筆數)。
    雜湊值和長度只留在記憶體，給海關比對用。"""
    entries = []
    secrets = {}  # 沒有網址而被略過的密碼（例如手機 App 的）也要記，海關一樣要擋
    skipped = 0
    for url, password in read_password_csv(csv_path):
        if password:
            secrets[sha1_hex(password)] = len(password.encode("utf-8"))
        domain = normalize_domain(url)
        if not domain or not password:
            skipped += 1
            continue
        entries.append((domain, hostname(url) or domain, sha1_hex(password), estimate_strength(password)))
    return entries, secrets, skipped


def check(entries):
    """查外洩、找重複，只用雜湊值。回傳摘要（每個帳號一筆：網域、外洩次數、有沒有重複、強度）。"""
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
    return summary
