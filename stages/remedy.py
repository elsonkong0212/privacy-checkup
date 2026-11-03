"""M4 補救建議：查你的每個網站支援哪種兩步驟驗證、怎麼刪除帳號。"""
from common import cached_json, normalize_domain

TFA_URL = "https://api.2fa.directory/v4/all.json"
JDM_URL = "https://raw.githubusercontent.com/jdm-contrib/jdm/master/_data/sites.json"


def load_indexes():
    """回傳 (2fa.directory 索引, JustDeleteMe 索引, 下載時間)，兩個索引都用主網域查。"""
    tfa, tfa_fetched = cached_json("2fa_directory.json", TFA_URL)
    jdm, jdm_fetched = cached_json("justdeleteme.json", JDM_URL)

    tfa_index = {}
    for domain, info in tfa.items():
        normalized = normalize_domain(domain)
        if normalized:
            tfa_index.setdefault(normalized, info)
    jdm_index = {}
    for site in jdm:
        for domain in site.get("domains", []):
            normalized = normalize_domain(domain)
            if normalized:
                jdm_index.setdefault(normalized, site)
    return tfa_index, jdm_index, {"2fa_fetched": tfa_fetched, "jdm_fetched": jdm_fetched}


def run(accounts):
    tfa_index, jdm_index, meta = load_indexes()
    result = []
    for account in accounts:
        info = tfa_index.get(account["domain"])
        site = jdm_index.get(account["domain"])
        result.append({
            "domain": account["domain"],
            # None = 資料庫沒收錄；[] = 有收錄但不支援兩步驟驗證
            "two_factor_methods": None if info is None else info.get("methods", []),
            "two_factor_doc": (info or {}).get("documentation"),
            "delete_difficulty": site.get("difficulty") if site else None,
            "delete_url": site.get("url") if site else None,
            "site_name": site.get("name") if site else None,  # 辨認看不懂的網站時給 AI 參考
        })
    return result, meta
