"""M3 外洩比對：拿你的帳號網域，比對 HIBP 收錄的所有已公開外洩事件。

只用公開的「外洩事件清單」（免費、不需要 API key），不會把你的 email 送出去。
"""
from common import cached_json, normalize_domain

BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


def load_breaches():
    """回傳 (真實的外洩事件, 下載時間, 收錄總數)。假造的資料和垃圾郵件名單不算。"""
    breaches, fetched = cached_json("hibp_breaches.json", BREACHES_URL)
    real = [b for b in breaches if not b.get("IsFabricated") and not b.get("IsSpamList")]
    return real, fetched, len(breaches)


def load_breach_index():
    breaches, fetched, total = load_breaches()
    index = {}
    for breach in breaches:
        domain = normalize_domain(breach.get("Domain") or "")
        if domain:
            index.setdefault(domain, []).append(breach)
    return index, fetched, total


def run(accounts):
    index, fetched, total = load_breach_index()
    found = []
    for account in accounts:
        for breach in index.get(account["domain"], []):
            found.append({
                "domain": account["domain"],
                "breach_name": breach["Title"],
                "breach_date": breach["BreachDate"],
                "data_classes": breach["DataClasses"],
                "pwn_count": breach["PwnCount"],
                "verified": breach["IsVerified"],
            })
    meta = {"fetched": fetched, "total": total, "tw_domains": sum(1 for d in index if d.endswith(".tw"))}
    return found, meta
