"""共用工具：路徑、個人資料資料夾、網域整理、日期整理、下載與快取、檔案讀寫。"""
import csv
import datetime
import json
import os
import re
import shutil
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

# 個人資料（密碼檔、帳號清單、Gmail 憑證）放在專案資料夾「外面」：
# 用 AI 工具打開這個專案時，工作區裡才不會有明文密碼檔。想換位置就設定環境變數 PRIVACY_CHECKUP_SECRETS。
SECRETS = (Path(os.environ["PRIVACY_CHECKUP_SECRETS"]).expanduser() if os.environ.get("PRIVACY_CHECKUP_SECRETS")
           else Path.home() / "privacy-checkup-secrets")
OLD_SECRETS = BASE / "secrets"  # 舊版放個人資料的位置（在專案資料夾裡）

# Public Suffix List：公開的「網域尾碼」清單（com.tw、co.th、github.io…），用來找出網址的主網域
SUFFIX_LIST = BASE / "resources" / "public_suffix_list.dat"
SUFFIX_LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
_suffix_rules = None


def prepare_secrets():
    """建立個人資料資料夾；舊版放在專案裡 secrets/ 的檔案自動搬過去，並印出搬了什麼。"""
    SECRETS.mkdir(parents=True, exist_ok=True)
    if not OLD_SECRETS.is_dir() or OLD_SECRETS.resolve() == SECRETS.resolve():
        return
    moved, kept = [], []
    for path in sorted(OLD_SECRETS.iterdir()):
        if not path.is_file():
            continue
        target = SECRETS / path.name
        if target.exists():
            kept.append(path.name)
        else:
            shutil.move(str(path), str(target))
            moved.append(path.name)
    if moved:
        print(f"[注意] 個人資料改放在專案資料夾外面：{SECRETS}")
        print(f"       已經把 secrets/ 裡的 {len(moved)} 個檔案搬過去：{'、'.join(moved)}")
    if kept:
        print(f"[注意] secrets/ 裡的 {'、'.join(kept)} 沒有搬：{SECRETS} 已經有同名的檔案。")
        print("       程式只會讀新位置的檔案，請確認後把 secrets/ 裡的舊檔刪掉。")
    if not any(OLD_SECRETS.iterdir()):
        OLD_SECRETS.rmdir()


def _load_suffix_rules():
    global _suffix_rules
    if _suffix_rules is None:
        if not SUFFIX_LIST.exists():
            raise SystemExit(f"找不到網域尾碼清單：{SUFFIX_LIST}\n請重新下載專案，或執行 python common.py 重新抓取。")
        rules = set()
        for line in SUFFIX_LIST.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            rules.add(rule)
            if not rule.isascii():  # 中文網域：網址裡可能寫成 xn-- 開頭的編碼，兩種寫法都要認得
                try:
                    rules.add(rule.encode("idna").decode("ascii"))
                except UnicodeError:
                    pass
        _suffix_rules = rules
    return _suffix_rules


def _suffix_length(labels):
    """網域尾碼佔了最後幾段：shopee.co.th → 2（co.th）、foo.github.io → 2（github.io）、shopee.tw → 1（tw）。"""
    rules = _load_suffix_rules()
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        if "!" + name in rules:  # 例外規則：這個名稱本身就是可以註冊的網域
            return len(labels) - i - 1
        if name in rules or "*." + ".".join(labels[i + 1:]) in rules:
            return len(labels) - i
    return 1  # 清單上沒有的尾碼（例如 .example）：當成只有最後一段


def normalize_domain(value):
    """把網址或網域整理成主網域：https://www.shopee.tw/login → shopee.tw、shopee.co.th/login → shopee.co.th

    尾碼有幾段是查 Public Suffix List 決定的，不是自己猜。github.io、myshopify.com 這類「每個人各有一個子網域」
    的平台也在清單上，所以 a.github.io 和 b.github.io 會算成兩個不同的網站。"""
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
    host = (host or "").rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host or host.replace(".", "").isdigit():
        return None
    labels = host.split(".")
    keep = _suffix_length(labels) + 1  # 尾碼再加一段就是主網域；網址本身就是尾碼的話，整個留著
    return ".".join(labels[-keep:])


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


def cached_json(name, url=None, max_age_hours=24, fetch=None):
    """下載公開資料並存在 data/cache，整個程式的下載快取都走這裡。回傳 (資料, 下載時間)。

    - 一天內不重複下載；max_age_hours=None 代表內容不會變，下載過就一直用
    - 下載失敗（連不上、網站回了看不懂的內容）但有舊的快取：印出提醒，改用舊的；沒有舊的才算失敗
    - fetch：自己提供下載方式的函式（回傳整理好的資料），例如要用 POST 的網站；不給就直接抓 url"""
    path = CACHE / name
    expired = max_age_hours is not None and path.exists() and time.time() - path.stat().st_mtime > max_age_hours * 3600
    if not path.exists() or expired:
        try:
            data = fetch() if fetch else json.loads(http_get(url, timeout=60).decode("utf-8"))
            save_json(path, data, indent=None)  # 內容看得懂才存，不會把錯誤頁面存成快取
        except (OSError, ValueError) as error:
            if not path.exists():
                raise
            print(f"  [注意] 下載 {name} 失敗，改用舊的快取：{error}")
    fetched = time.strftime("%Y-%m-%d %H:%M", time.localtime(path.stat().st_mtime))
    return load_json(path), fetched


def read_csv_rows(path):
    # 用 Excel 存檔時可能會存成 Big5（cp950），兩種都試
    for encoding in ("utf-8-sig", "cp950"):
        try:
            with open(path, newline="", encoding=encoding) as f:
                return list(csv.DictReader(f))
        except UnicodeDecodeError:
            continue
    raise SystemExit(f"讀不懂 {path} 的文字編碼，請用 UTF-8 存檔")


def load_json(path, default=None):
    """讀 JSON 檔；檔案不存在就回傳 default。"""
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def save_json(path, data, indent=2):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=indent), encoding="utf-8")


if __name__ == "__main__":
    # 用法（在 privacy-checkup 資料夾裡）：python common.py　→ 更新 resources/ 裡的網域尾碼清單
    SUFFIX_LIST.parent.mkdir(exist_ok=True)
    SUFFIX_LIST.write_bytes(http_get(SUFFIX_LIST_URL, timeout=60))
    print(f"已更新 {SUFFIX_LIST}：{len(_load_suffix_rules()):,} 條規則")
