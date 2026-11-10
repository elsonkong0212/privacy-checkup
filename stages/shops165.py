"""165 高風險賣場名單：自動從 165 全民防騙網抓取，再加上手動補充的店名。

兩個來源都是 165 網站本身在用的公開查詢介面，不需要登入：
1. 高風險賣場查詢：一次取得 2022/01～2025/10 的每週名單（結構化資料）
2. 「民眾通報高風險業者」每週公告：2026/08 起改用公告發布，從文章內文解析店名
   （2025/10～2026/08 之間 165 沒有發布每週名單）

這不是官方文件化的 API，網站改版就可能失效；抓不到時會印出提醒，改成只用手動整理的 165_shops.csv。
"""
import csv
import html
import json
import re
import ssl
import time
import urllib.request
from pathlib import Path

from common import USER_AGENT, cached_json, parse_date, read_csv_rows

BASE_URL = "https://165.npa.gov.tw"
WEEKLY_TITLE = re.compile(r"(\d{3})/(\d{2})/(\d{2})\s*-\s*(?:(\d{3})/)?(\d{2})/(\d{2})\s*(?:統計)?民眾通報高風險業者")
SENTENCE_MARKS = re.compile(r"[，。！？!?：:；;]")

# Python 3.13 起預設啟用嚴格的憑證檢查，台灣政府網站的憑證缺少 Subject Key Identifier 欄位會被擋下。
# 這裡仍然完整驗證憑證，只關掉這一項嚴格檢查。
_SSL = ssl.create_default_context()
_SSL.verify_flags &= ~ssl.VERIFY_X509_STRICT


def _request(path, body=None):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json;charset=UTF-8"
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=60, context=_SSL) as response:
        return json.loads(response.read().decode("utf-8"))


def shop_key(name):
    """同一家店的不同寫法（CACO、Caco、「蝦皮 購物」）要算成同一個：去掉空白、不分大小寫。"""
    return re.sub(r"\s+", "", name).casefold()


def roc_period(title):
    """「114/12/27-01/02民眾通報高風險業者」→ ("2025-12-27", "2026-01-02")。民國年加 1911。"""
    match = WEEKLY_TITLE.search(title or "")
    if not match:
        return None
    y1, m1, d1, y2, m2, d2 = match.groups()
    start_year = int(y1) + 1911
    end_year = int(y2) + 1911 if y2 else start_year + (1 if int(m2) < int(m1) else 0)
    return f"{start_year}-{m1}-{d1}", f"{end_year}-{m2}-{d2}"


def parse_names(content):
    """從每週公告內文取出店名：一行一個，遇到「請慎防…」那段提醒就停。"""
    names = []
    for part in re.split(r"<br\s*/?>|</p>|</div>|</li>|\n", content or ""):
        line = html.unescape(re.sub(r"<[^>]+>", "", part)).replace("\xa0", " ").strip()
        if not line or WEEKLY_TITLE.search(line):
            continue
        if line.startswith("請慎防"):
            break
        line = re.sub(r"^\d+\s*[.、)）]\s*", "", line)  # 去掉「1.」這類編號
        if len(line) <= 30 and not line.startswith("#") and not SENTENCE_MARKS.search(line) and line not in names:
            names.append(line)
    return names


def fetch_history():
    records, _ = cached_json("165_history.json", fetch=lambda: _request("/api/query/findRiskMarket", {"keyWord": ""}))
    return [{"shop_name": r["storeName"].strip(), "start": r["statisticsStartDate"][:10],
             "end": r["statisticsEndDate"][:10]} for r in records if r.get("storeName")]


def _fetch_article(article_id):
    time.sleep(0.5)  # 對政府網站客氣一點
    return _request(f"/api/article/detail/9/{article_id}")


def fetch_weekly(after):
    """抓 after（YYYY-MM-DD）之後的每週公告。公告內容不會變，每篇只下載一次。"""
    articles, _ = cached_json("165_articles.json", fetch=lambda: _request("/api/article/list/9"))
    entries, unreadable = [], []
    for article in articles:
        period = roc_period(article.get("title"))
        if not period or period[1] <= after:
            continue
        try:
            detail, _ = cached_json(f"165_weekly/{article['id']}.json", max_age_hours=None,
                                    fetch=lambda: _fetch_article(article["id"]))
        except (OSError, ValueError):  # 這一篇下載不到：先略過，其他已經下載過的照用
            unreadable.append(article.get("title"))
            continue
        names = parse_names(detail.get("content"))
        if not names:
            unreadable.append(article.get("title"))
        entries += [{"shop_name": n, "start": period[0], "end": period[1]} for n in names]
    weeks = len({(e["start"], e["end"]) for e in entries})
    return entries, weeks, unreadable


def load(manual_path=None, fetch=True):
    """回傳 (店家清單, 說明)。同一家店的不同寫法（CACO、Caco）會合併，並記下被列入幾次、最近一次是哪一週。

    手動清單可以只有 shop_name 一欄；如果有 times、last_listed（例如 templates/ 裡的快照），離線時也能用。
    手動清單裡已經在自動名單上的店名不會重複計算。"""
    entries, meta = [], {"history": None, "weekly_weeks": 0, "manual": 0, "warning": None}
    if fetch:
        try:
            history = fetch_history()
            entries += history
            if history:
                meta["history"] = (min(e["start"] for e in history), max(e["end"] for e in history))
            weekly, meta["weekly_weeks"], unreadable = fetch_weekly(after=meta["history"][1] if meta["history"] else "")
            entries += weekly
            if unreadable:
                print(f"  [注意] 有 {len(unreadable)} 篇公告下載不到或格式看不懂，已略過：{unreadable[:3]}")
        except Exception as error:  # 網站改版、連不上
            meta["warning"] = f"自動抓取 165 名單失敗（{error}），只用手動清單"
            print(f"  [注意] {meta['warning']}")
    shops = {}
    for e in entries:
        shop = shops.setdefault(shop_key(e["shop_name"]), {"shop_name": e["shop_name"], "times": 0, "last_listed": None})
        shop["times"] += 1
        if not shop["last_listed"] or e["end"] > shop["last_listed"]:
            shop["last_listed"], shop["shop_name"] = e["end"], e["shop_name"]  # 用最近一次的寫法

    if manual_path and Path(manual_path).exists():
        for row in read_csv_rows(manual_path):
            name = (row.get("shop_name") or "").strip()
            if not name or shop_key(name) in shops:
                continue
            times = (row.get("times") or "").strip()
            shops[shop_key(name)] = {"shop_name": name, "times": int(times) if times.isdigit() else 0,
                                 "last_listed": parse_date(row.get("last_listed"))}
            meta["manual"] += 1

    ordered = sorted(shops.values(), key=lambda s: s["last_listed"] or "9999", reverse=True)
    return [{"shop_id": f"shop_{i}", **s} for i, s in enumerate(ordered, 1)], meta


def export(path):
    """把目前抓到的完整名單存成 CSV（templates/165_shops.csv 的快照就是這樣產生的）。"""
    shops, meta = load(fetch=True)
    if meta["warning"]:
        raise SystemExit(meta["warning"])
    note = f"165 自動抓取（{time.strftime('%Y-%m-%d')}）"
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # 加 BOM，用 Excel 打開中文才不會亂碼
        writer = csv.writer(f)
        writer.writerow(["shop_name", "times", "last_listed", "note"])
        for s in sorted(shops, key=lambda s: (s["last_listed"] or "", s["times"]), reverse=True):
            writer.writerow([s["shop_name"], s["times"], s["last_listed"] or "", note])
    print(f"已寫入 {path}：{len(shops)} 家（查詢資料 {meta['history'][0]}～{meta['history'][1]}、"
          f"每週公告 {meta['weekly_weeks']} 週）")


if __name__ == "__main__":
    # 用法（在 privacy-checkup 資料夾裡）：python -m stages.shops165 templates/165_shops.csv
    import sys
    sys.stdout.reconfigure(errors="replace")
    export(sys.argv[1] if len(sys.argv) > 1 else "165_shops.csv")
