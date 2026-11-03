"""共用工具：路徑、網域整理、日期整理、下載與快取、檔案讀寫。"""
import csv
import datetime
import json
import re
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
CACHE = DATA / "cache"
OUTPUT = BASE / "output"
AUDIT_LOG = BASE / "audit.log"
USER_AGENT = "privacy-checkup (personal security self-check)"

# 常見的兩層網域尾碼：shop.com.tw 的主網域是 shop.com.tw，不是 com.tw
MULTI_LEVEL_SUFFIXES = {
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw", "game.tw", "ebiz.tw", "club.tw",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.cn", "net.cn", "org.cn", "com.hk", "org.hk", "com.sg", "com.my", "com.au", "net.au",
    "co.kr", "com.br", "co.nz", "co.in", "com.mx", "com.tr",
}


def normalize_domain(value):
    """把網址或網域整理成主網域：https://www.shopee.tw/login → shopee.tw"""
    if not value:
        return None
    value = value.strip().lower()
    if value.startswith("android://"):  # Chrome 匯出的手機 App 項目，沒有網域
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        host = urlparse(value).hostname
    except ValueError:
        return None
    if not host or "." not in host or host.replace(".", "").isdigit():
        return None
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def hostname(value):
    """網址的完整主機名稱（去掉 www.）：https://moodle.ncku.edu.tw/login → moodle.ncku.edu.tw"""
    if not value or value.strip().lower().startswith("android://"):
        return None
    value = value.strip().lower()
    try:
        host = urlparse(value if "://" in value else "http://" + value).hostname
    except ValueError:
        return None
    return host[4:] if host and host.startswith("www.") else host


def parse_date(value):
    """把各種日期寫法統一成 YYYY-MM-DD，才能正確比較先後。

    用 Excel 編輯過的 CSV，日期常被改成 2022/5/23 這種寫法；直接拿文字比較會出錯。看不懂就回傳 None。"""
    text = str(value or "").strip()
    match = re.match(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", text)
    if match:
        year, month, day = map(int, match.groups())
    else:
        match = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", text)  # 美式寫法 M/D/YYYY
        if not match:
            return None
        month, day, year = map(int, match.groups())
    try:
        return datetime.date(year, month, day).isoformat()
    except ValueError:
        return None


def http_get(url, headers=None, timeout=30):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def cached_json(name, url, max_age_hours=24):
    """下載公開資料並快取在 data/cache，一天內不重複下載。回傳 (資料, 下載時間)。"""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / name
    if not path.exists() or time.time() - path.stat().st_mtime > max_age_hours * 3600:
        try:
            path.write_bytes(http_get(url, timeout=60))
        except OSError as error:
            if not path.exists():
                raise
            print(f"  [注意] 下載 {url} 失敗，改用舊的快取：{error}")
    fetched = time.strftime("%Y-%m-%d %H:%M", time.localtime(path.stat().st_mtime))
    return json.loads(path.read_text(encoding="utf-8")), fetched


def read_csv_rows(path):
    # 用 Excel 存檔時可能會存成 Big5（cp950），兩種都試
    for encoding in ("utf-8-sig", "cp950"):
        try:
            with open(path, newline="", encoding=encoding) as f:
                return list(csv.DictReader(f))
        except UnicodeDecodeError:
            continue
    raise SystemExit(f"讀不懂 {path} 的文字編碼，請用 UTF-8 存檔")


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
