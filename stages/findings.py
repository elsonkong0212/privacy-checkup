"""把各階段的結果整理成一筆一筆的「證據」，每筆都附上規則判斷的預設等級和說明。

AI 只能在這些證據的基礎上調整優先順序、改寫說明；AI 沒回覆或回覆不合格時，就用這裡的預設值。
"""
import datetime
from collections import Counter, defaultdict

from common import parse_date

LEVELS = ("red", "yellow", "green")

DATA_CLASS_ZH = {
    "Email addresses": "email", "Passwords": "密碼", "Usernames": "使用者名稱", "Names": "姓名",
    "Phone numbers": "電話號碼", "Physical addresses": "地址", "Dates of birth": "生日",
    "IP addresses": "IP 位址", "Credit cards": "信用卡", "Partial credit card data": "部分信用卡資料",
    "Genders": "性別", "Geographic locations": "地理位置", "Password hints": "密碼提示",
    "Security questions and answers": "安全提問與答案", "Employers": "雇主", "Job titles": "職稱",
    "Social media profiles": "社群帳號", "Purchases": "購買紀錄", "Bank account numbers": "銀行帳號",
}
TFA_METHOD_ZH = {
    "totp": "驗證器 App", "u2f": "實體安全金鑰", "sms": "簡訊", "email": "email 驗證碼",
    "call": "語音電話", "custom-software": "官方 App", "custom-hardware": "官方硬體裝置",
}
DIFFICULTY_ZH = {"easy": "容易", "medium": "普通", "hard": "困難", "impossible": "無法刪除", "limited": "只能部分刪除"}


def zh_classes(classes):
    return "、".join(DATA_CLASS_ZH.get(c, c) for c in classes)


def zh_methods(methods):
    return "、".join(TFA_METHOD_ZH.get(m, m) for m in methods)


def build_evidence(pw_summary, accounts, breaches, remedies, shop_matches):
    evidence = []
    counters = Counter()

    def add(prefix, **item):
        counters[prefix] += 1
        item["id"] = f"{prefix}{counters[prefix]}"
        evidence.append(item)

    first_seen = {a["domain"]: parse_date(a.get("first_seen")) for a in accounts}

    def registered_after(breach):
        """最早收到這個網站來信的日期比外洩晚 → 帳號很可能是外洩之後才註冊的。"""
        seen = first_seen.get(breach["domain"])
        return bool(seen) and seen > breach["breach_date"]

    # 外洩過密碼、而且可能有你資料的網站：用來判斷「重複使用的密碼」是不是已經跟著外洩
    password_breached = {b["domain"] for b in breaches
                         if "Passwords" in b["data_classes"] and not registered_after(b)}

    # P：已外洩的密碼
    for s in pw_summary:
        if s["pwned_count"]:
            add("P", kind="pwned_password", domain=s["domain"], pwned_count=s["pwned_count"], reused=s["reused"],
                source="HIBP Pwned Passwords（只送出雜湊值前 5 碼）", default_level="red",
                default_reason=f"這組密碼在外洩密碼庫裡出現過 {s['pwned_count']:,} 次，壞人很可能會拿它來試著登入。"
                               + ("而且你在其他網站也用了同一組密碼。" if s["reused"] else ""),
                default_action=f"立刻到 {s['domain']} 換一組新的、沒在其他地方用過的密碼。")

    # R：重複使用、但沒出現在外洩密碼庫的密碼（同一組密碼的外洩次數一定相同，外洩的已經在 P 處理）
    groups = defaultdict(list)
    for s in pw_summary:
        if s["reuse_group"] and not s["pwned_count"]:
            groups[s["reuse_group"]].append(s)
    reuse_ids = {}
    for members in groups.values():
        domains = sorted({m["domain"] for m in members})
        hosts = Counter(m.get("host") or m["domain"] for m in members)
        breached = [d for d in domains if d in password_breached]
        where = (f"{len(members)} 個帳號（分布在 {len(domains)} 個網站）" if len(domains) > 1
                 else f"{domains[0]} 底下的 {len(members)} 個帳號")
        if breached:
            # 連鎖風險：其中一個網站外洩過密碼，整組密碼都可能已經在壞人手上
            level = "red"
            reason = (f"這組密碼用在 {where}。其中 {'、'.join(breached)} 曾經外洩過密碼，"
                      "如果外洩時你已經有帳號，壞人可能已經拿到這組密碼，其他帳號也會跟著被登入。")
            action = "立刻把這些帳號的密碼全部換掉，每個網站用不同的密碼；從 email、學校、銀行這類重要帳號先換。"
        else:
            level = "yellow"
            reason = f"這組密碼用在 {where}。只要其中一個網站外洩，其他帳號也會跟著被登入。"
            action = "幫這些帳號各換成不同的密碼，先從最重要的換。"
        add("R", kind="reused_password", domain=domains[0], domains=domains, accounts=len(members),
            hosts=[f"{host} ×{n}" if n > 1 else host for host, n in sorted(hosts.items())],
            breached_in_group=breached,
            source="密碼檢查（本機比對）" + ("＋HIBP 外洩事件清單" if breached else ""),
            default_level=level, default_reason=reason, default_action=action)
        for domain in domains:
            reuse_ids[domain] = evidence[-1]["id"]

    # W：太弱、但沒外洩也沒重複的密碼
    for s in pw_summary:
        if s["strength"] <= 1 and not s["pwned_count"] and not s["reused"]:
            add("W", kind="weak_password", domain=s["domain"], source="密碼檢查（本機估計強度）",
                default_level="yellow",
                default_reason=f"{s['domain']} 的密碼強度「{s['strength_label']}」，容易被猜中。",
                default_action=f"把 {s['domain']} 的密碼換成更長的（建議 14 個字元以上，或用密碼管理器產生）。")

    # B：帳號所在的網站曾經外洩
    for b in breaches:
        has_password = "Passwords" in b["data_classes"]
        seen = first_seen.get(b["domain"])
        what = f"{b['domain']} 在 {b['breach_date']} 發生外洩（{b['breach_name']}），外洩的資料包含：{zh_classes(b['data_classes'])}。"
        if registered_after(b):
            level = "yellow" if has_password else "green"
            reason = (what + f"不過你最早收到這個網站的信是 {seen}，比外洩晚，帳號很可能是外洩之後才註冊的，"
                      "這次外洩應該沒有你的資料（如果你刪過舊信，這個判斷可能不準）。")
            action = "應該不受這次外洩影響；保險起見，確認這個網站的密碼沒有在別的地方重複使用。"
        elif has_password:
            level = "red"
            reason = what + (f"你在這個網站用的密碼，還用在其他帳號（見 {reuse_ids[b['domain']]}）。"
                             if b["domain"] in reuse_ids else "")
            action = (f"如果你在 {b['breach_date']} 之後沒有換過 {b['domain']} 的密碼，現在就換；"
                      "用同一組密碼的其他網站也一起換。")
        else:
            level, reason = "yellow", what
            action = "留意假冒這個網站名義的信件和電話，不要點信裡的連結。"
        add("B", kind="breach", domain=b["domain"], breach_name=b["breach_name"], breach_date=b["breach_date"],
            data_classes=b["data_classes"], first_seen=seen, source="HIBP 外洩事件清單",
            default_level=level, default_reason=reason, default_action=action)

    # S：可能是 165 公布的高風險賣場（一年內被列入過算「這週處理」，更早的算「有空再處理」）
    recent = (datetime.date.today() - datetime.timedelta(days=365)).isoformat()
    shops_by_domain = defaultdict(list)  # 同一個網站可能對到好幾種寫法（PChome、Pchome商店街），合併成一筆
    for m in shop_matches:
        shops_by_domain[m["domain"]].append(m)
    for domain, matches in shops_by_domain.items():
        names = "、".join(f"「{m['shop_name']}」" for m in matches)
        times = sum(m.get("times", 0) for m in matches)
        listed = max((m["last_listed"] for m in matches if m.get("last_listed")), default=None)
        by_ai = any(m["by"] == "AI" for m in matches)
        history = (f"在 165 名單上出現過 {times} 次，最近一次是 {listed} 那週。" if listed
                   else "在你手動整理的 165 名單上。")
        add("S", kind="high_risk_shop", domain=domain, shop_name="、".join(m["shop_name"] for m in matches),
            confidence="high" if any(m["confidence"] == "high" for m in matches) else "medium",
            times=times, last_listed=listed,
            source=f"165 高風險賣場名單（{'店名對應的網域是 AI 翻譯的' if by_ai else '規則比對'}，請自己確認）",
            ai_guess=by_ai, default_level="yellow" if not listed or listed >= recent else "green",
            default_reason=f"{domain} 可能就是 165 公布的高風險賣場{names}，{history}"
                           "被列入代表很多人接到冒用這家名義的詐騙電話，不一定是業者本身被駭。",
            default_action="接到自稱這家客服的電話時，不要照指示操作 ATM 或網路銀行，先掛掉再打 165 查證。")

    # T：可以開兩步驟驗證；D：標記不再使用、建議刪除
    still_using = {a["domain"]: a["still_using"] for a in accounts}
    risky = {e["domain"] for e in evidence if e["kind"] in ("pwned_password", "breach")}
    risky |= {d for e in evidence if e["kind"] == "reused_password" and e["default_level"] == "red" for d in e["domains"]}
    for r in remedies:
        if still_using.get(r["domain"]) is False:
            difficulty = DIFFICULTY_ZH.get(r["delete_difficulty"])
            add("D", kind="delete_account", domain=r["domain"], delete_difficulty=r["delete_difficulty"],
                link=r["delete_url"], source="JustDeleteMe" if difficulty else "你的帳號清單",
                default_level="green",
                default_reason="你標記這個帳號已經不用了。沒人顧的帳號外洩了，你也不會知道。",
                default_action=f"刪除這個帳號（難易度：{difficulty}）。" if difficulty
                               else "到網站的帳號設定找刪除選項，找不到就寫信給客服要求刪除。")
        elif r["two_factor_methods"]:
            add("T", kind="enable_2fa", domain=r["domain"], two_factor_methods=r["two_factor_methods"],
                link=r["two_factor_doc"], source="2fa.directory",
                default_level="yellow" if r["domain"] in risky else "green",
                default_reason=f"{r['domain']} 支援兩步驟驗證（{zh_methods(r['two_factor_methods'])}）。"
                               "開啟後，就算密碼外洩，壞人也很難登入。",
                default_action=f"如果還沒開，到 {r['domain']} 開啟兩步驟驗證。")
    return evidence


KIND_ZH = {"pwned_password": "密碼出現在外洩密碼庫", "reused_password": "共用同一組密碼", "weak_password": "密碼太弱",
           "breach": "外洩事件", "high_risk_shop": "165 高風險賣場", "lookalike_domain": "疑似仿冒網站",
           "enable_2fa": "可以開兩步驟驗證", "delete_account": "建議刪除的帳號"}
# 程式沒辦法自己確認「處理了沒」的項目，才能由你標記已處理（python main.py --done B1）。
# 密碼類（P、R、W）不行：換完密碼、重新匯出密碼檔再跑一次，程式會自己重新檢查，處理好了就會消失
DONE_KINDS = {"breach", "high_risk_shop", "lookalike_domain", "enable_2fa", "delete_account"}


def assign_keys(evidence):
    """幫每一筆加上「不會變的編號」key 和一行標題 title。

    報告上的 P1、B2 是流水號，帳號多一個少一個就會變；key 是用種類、網站、事件名稱組成的，
    同一個問題每次都一樣，用來比較前後兩次的結果、記住你標記已處理的項目。key 和 title 都不會交給 AI。"""
    seen = Counter()
    for e in evidence:
        kind, domain = e["kind"], e["domain"]
        if kind == "breach":
            key, title = f"breach|{domain}|{e['breach_name']}", f"{domain}：外洩事件「{e['breach_name']}」"
        elif kind == "reused_password":
            key, title = "reused_password|" + ",".join(e["hosts"]), f"{'、'.join(e['hosts'])}：{KIND_ZH[kind]}"
        elif kind == "lookalike_domain":
            key, title = f"{kind}|{domain}|{e['official_domain']}", f"{domain}：{KIND_ZH[kind]}"
        else:
            key, title = f"{kind}|{domain}", f"{domain}：{KIND_ZH.get(kind, kind)}"
        seen[key] += 1  # 同一個網站有兩個帳號的密碼都外洩時，key 會一樣，第二個起加上 #2
        e["key"], e["title"] = (key if seen[key] == 1 else f"{key}#{seen[key]}"), title
    return evidence


def marked_done(e, done):
    """這一筆是不是你標記過已處理的。done：{key: {date, title}}（stages/history.py）。"""
    return e["kind"] in DONE_KINDS and e.get("key") in done


def finalize(evidence, overrides, done=None):
    """套用 AI 改寫的說明（overrides：{證據編號: {reason, action}}）和你標記的已處理（done）。

    燈號只看規則判斷的 default_level，AI 改不了：同一份資料不管跑幾次、用哪一種 AI，燈號都一樣。
    網站對應是 AI 推測的項目，最多只到 🟡。你標記已處理的項目 level 是 done，不列入燈號，報告另外列出來。"""
    final, done = [], done or {}
    for e in evidence:
        override = overrides.get(e["id"])
        level = "yellow" if e.get("ai_guess") and e["default_level"] == "red" else e["default_level"]
        if marked_done(e, done):
            level, e = "done", {**e, "done_date": done[e["key"]].get("date")}
        final.append({**e, "level": level,
                      "reason": override["reason"] if override else e["default_reason"],
                      "action": override["action"] if override else e["default_action"],
                      "ai_written": bool(override)})
    return final
