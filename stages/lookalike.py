"""仿冒網域偵測：你的帳號裡，有沒有長得很像 165 店家官方網域、但其實不是同一個的網站？

165 名單上的店家常被詐騙集團冒用。如果你曾經點廣告、簡訊連結，在仿冒的假網站上註冊或輸入密碼，
密碼可能已經在壞人手上。

1. 程式在你的電腦上比對（不用 AI）：拿 AI 翻好的 165 店家官方網域（shop_domains.json），找出名稱很像的帳號網站
   - 品牌字出現在網址裡：shopee-tw-service.com、shopee.tw.verify-login.com（藏在子網域裡）
   - 只差一兩個字：shoppee.tw
   - 名稱一樣但尾碼不同：shopee.com.co
2. 只有這些可疑的網站才交給 AI 判斷：同一家公司的官方分站、仿冒的假網站，還是剛好名字很像（ai_steps.check_lookalikes）
   判斷結果存在 data/cache/lookalike_verdicts.json，同一個網站之後直接沿用，每次的報告才會一樣
3. AI 判斷是仿冒的列為 🔴；沒有 AI 或 AI 沒把握的列為 🟡，請你自己確認
4. AI 判斷是官方分站或不相關的不列入燈號，但報告會另外列出來給你確認：AI 也可能判斷錯，網址又是騙子自己取的，
   不能讓 AI 悄悄把警告拿掉
"""
import re

# 太常見的字當品牌會一直誤報（例如 shop、life）
GENERIC_BRANDS = {"shop", "store", "online", "mall", "official", "taiwan", "www", "com", "net", "buy", "home", "life",
                  "love", "good", "best", "club", "plus", "live", "news", "care", "beauty", "fashion", "design", "line"}
LEVEL_BY_VERDICT = {"imitation": "red", "unsure": "yellow", None: "yellow"}


def _label(domain):
    """主網域的第一段：shopee.tw → shopee、pchome.com.tw → pchome"""
    return domain.split(".")[0]


def _distance(a, b):
    """兩個字串要改幾個字才會一樣（編輯距離）。"""
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _why(host, domain, brand):
    """這個網址為什麼看起來像這個品牌；不像就回傳 None。"""
    label = _label(domain)
    tokens = re.split(r"[^a-z0-9]+", host.lower())
    if brand in tokens and label != brand:
        return f"網址裡有「{brand}」"
    if len(brand) >= 6 and brand in label and label != brand:
        return f"網址裡有「{brand}」"
    if label == brand:
        return "名稱一樣，但網域尾碼不同"
    if len(brand) >= 5 and abs(len(label) - len(brand)) <= 2 and _distance(label, brand) <= (1 if len(brand) < 8 else 2):
        return f"和「{brand}」只差一兩個字"
    return None


def find_candidates(accounts, pw_summary, translations):
    """回傳可疑的網站清單。translations 是 165 店名翻成網域的快取（shop_domains.json）。"""
    officials = {}
    for key, entry in translations.items():
        for domain in entry.get("domains", []):
            officials.setdefault(domain, entry.get("shop_name") or key)
    brands = {}
    for domain, shop in officials.items():
        brand = _label(domain)
        if len(brand) >= 4 and brand not in GENERIC_BRANDS:
            brands.setdefault(brand, (domain, shop))
    # 要檢查的網址：每個帳號的網域，加上密碼檔裡的完整主機名稱（品牌字可能藏在子網域裡）
    hosts = {a["domain"]: a["domain"] for a in accounts}
    for s in pw_summary:
        if s.get("host"):
            hosts.setdefault(s["host"], s["domain"])
    candidates, seen = [], set()
    for host, domain in sorted(hosts.items()):
        if domain in officials:
            continue  # 這就是官方網域本身
        for brand, (official, shop) in brands.items():
            why = _why(host, domain, brand)
            if why and (domain, official) not in seen:
                seen.add((domain, official))
                candidates.append({"id": f"L{len(candidates) + 1}", "domain": domain, "host": host,
                                   "official_domain": official, "shop_name": shop, "why": why})
    return candidates


def build_items(candidates, verdicts):
    """把可疑的網站整理成證據。AI 判斷是官方分站或不相關的不當成問題，另外回傳讓報告列出來給你確認。
    回傳 (證據, 被 AI 排除的網站)。"""
    items, cleared = [], []
    for c in candidates:
        verdict = verdicts.get(c["id"])
        kind = verdict["verdict"] if verdict else None
        reason = (verdict.get("reason") or "").rstrip("。") if verdict else ""  # 理由沒通過檢查時是空的，結論照樣用
        if kind in ("official", "unrelated"):
            cleared.append({"domain": c["domain"], "host": c["host"], "official_domain": c["official_domain"],
                            "shop_name": c["shop_name"], "verdict": kind,
                            "reason": reason or "（AI 的理由沒通過檢查，已省略）"})
            continue
        what = (f"{c['host']} 的名稱很像 165 公布的店家「{c['shop_name']}」的官方網站 {c['official_domain']}"
                f"（{c['why']}），但不是同一個網域。")
        if kind == "imitation":
            judged = "AI 判斷很可能是仿冒的假網站" + (f"：{reason}。" if reason else "。")
        elif kind == "unsure":
            judged = "AI 也沒有把握" + (f"：{reason}。" if reason else "。")
        else:
            judged = "如果你是點廣告或簡訊連結進去的，可能是仿冒網站。"
        items.append({
            "id": c["id"], "kind": "lookalike_domain", "domain": c["domain"], "official_domain": c["official_domain"],
            "shop_name": c["shop_name"], "default_level": LEVEL_BY_VERDICT[kind],
            "source": "165 店家官方網域（AI 翻譯）＋本機比對" + ({"imitation": "；AI 判斷：仿冒",
                                                         "unsure": "；AI 判斷：沒把握"}.get(kind, "；未經 AI 判斷")),
            "default_reason": what + judged,
            "default_action": (f"不要再登入 {c['domain']}；如果在上面輸入過密碼，立刻到真正的 {c['official_domain']} 改密碼，"
                               "其他用同一組密碼的網站也一起換；留過信用卡的話，請留意帳單。"),
        })
    return items, cleared
