"""AI 負責的工作：Gmail 寄件者判斷、辨認看不懂的網站、165 店名翻成網域、仿冒網域判斷、排優先順序、寫總結。每一件都：
- 只透過 guard.ask_llm 呼叫 AI（過海關、留紀錄），AI 沒有任何工具
- 要求 AI 只回傳 JSON，回來後逐筆檢查，不合格的丟掉
- AI 不能用、失敗或回覆不合格時，改用規則判斷，報告照樣產生
"""
import json
import re

import guard
from common import normalize_domain
from stages.findings import LEVELS

SYSTEM_PROMPT = (
    "你是個人資安健檢報告的助手。只能根據使用者提供的 JSON 資料回答，"
    "不可以編造網站、外洩事件、日期或數字。使用台灣繁體中文、一般人聽得懂的用語。"
    "只輸出 JSON，不要加任何說明文字或 Markdown。"
)

TRANSLATE_INSTRUCTIONS = """\
下面是台灣 165 全民防騙網公布的高風險賣場店名（shops），全部是公開資料。
請判斷每個店名指的是哪個網站，回傳它的主網域（例如「蝦皮購物」→ shopee.tw）。
規則：
- 只列你有把握的店名；不知道的不要列，不要猜（名單很長，很多店家你不會認得）
- 一家店可以有好幾個網域（例如台灣站和國際站），最多 3 個
- 只在 Facebook、IG 上經營、沒有自己網站的小賣場，不要列
只輸出 JSON 陣列，格式：
[{"shop_id": "shop_1", "domains": ["shopee.tw"], "confidence": "high"}]
confidence 只能是 high 或 medium。"""

PRIORITIZE_INSTRUCTIONS = """\
下面是一份個人資安健檢找到的問題清單（evidence），每一筆都有規則判斷的預設等級 default_level。
請針對每一筆：
1. 判斷處理的急迫程度 level：red（立刻處理）、yellow（這週處理）、green（有空再處理）
2. 用一般人聽得懂的話寫 reason（為什麼要處理，一到兩句）
3. 寫 action（具體該做什麼，一句話）
規則：只能使用資料裡的事實，不可以提到資料裡沒有的網站或數字；每一筆都要回傳。
kind 的意思：pwned_password=密碼出現在外洩密碼庫；reused_password=多個網站用同一組密碼；
weak_password=密碼太弱；breach=這個網站曾經外洩；high_risk_shop=可能是 165 公布的高風險賣場（被冒名詐騙）；
lookalike_domain=名稱很像 165 店家官方網域（official_domain）、可能是仿冒的假網站，在上面輸入過密碼就要立刻處理。
first_seen 是使用者最早收到這個網站來信的日期，大約等於註冊時間；如果比 breach_date 晚，
帳號很可能是外洩之後才註冊的，這次外洩應該沒有他的資料（但他如果刪過舊信，這個判斷可能不準）。
reused_password 的 accounts 是這組密碼用在幾個帳號；breached_in_group 是這些網站裡曾經外洩過密碼的網站，
有的話代表這組密碼可能已經跟著外洩，所有用這組密碼的帳號都有風險。
high_risk_shop 的 times 是這家店被 165 列入高風險名單的次數，last_listed 是最近一次被列入的那週，越近越要注意。
只輸出 JSON 陣列，格式：
[{"id": "P1", "level": "red", "reason": "…", "action": "…"}]"""

SUMMARY_INSTRUCTIONS = """\
根據下面的統計數字（counts）和最優先的問題（top_findings），用 3 到 5 句話寫一段給本人看的總結：
整體狀況如何、最該先做的 1 到 3 件事是什麼。
規則：只能提到資料裡出現的網站和數字；語氣冷靜，不要恐嚇。
只輸出 JSON，格式：{"summary": "…"}"""

PRIORITIZE_KINDS = {"pwned_password", "reused_password", "weak_password", "breach", "high_risk_shop", "lookalike_domain"}
DOMAIN_TOKEN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
URL = re.compile(r"https?://[^\s<>()（）「」，。、]+", re.IGNORECASE)
EVIDENCE_ID = re.compile(r"\b[PRWBSTD]\d+\b")
ALWAYS_OK_DOMAINS = {"npa.gov.tw", "haveibeenpwned.com"}


def _parse_json(reply, expected_type):
    if not reply:
        return None
    open_char, close_char = ("[", "]") if expected_type is list else ("{", "}")
    start, end = reply.find(open_char), reply.rfind(close_char)
    if start < 0 or end <= start:
        return None
    try:
        value = json.loads(reply[start:end + 1])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, expected_type) else None


def _ask(task, instructions, data, expected_type):
    try:
        reply = guard.ask_llm(task, SYSTEM_PROMPT, instructions, data)
    except guard.Blocked as error:
        print(f"  [擋下] 海關攔截：{error}。這一步改用規則判斷")
        return None
    except Exception as error:  # CLI 失敗、逾時等
        print(f"  [注意] AI 呼叫失敗（{error}）。這一步改用規則判斷")
        return None
    if reply is None:
        return None  # 離線模式
    value = _parse_json(reply, expected_type)
    if value is None:
        print("  [注意] AI 回覆的格式不對。這一步改用規則判斷")
    return value


def _text_ok(text, known_domains):
    """AI 寫的文字只能提到已知的網站（網址只看網域，不看後面的路徑，例如 xxx.html）。"""
    if not isinstance(text, str) or not 0 < len(text.strip()) <= 300:
        return False
    for token in URL.findall(text) + DOMAIN_TOKEN.findall(URL.sub(" ", text)):
        domain = normalize_domain(token)
        if domain and domain not in known_domains and domain not in ALWAYS_OK_DOMAINS:
            return False
    return True


def _short_ok(text, allowed, limit):
    return isinstance(text, str) and len(text.strip()) <= limit and _text_ok(text, allowed)


# ---------- 寄件者名稱：送給 AI 之前先整理 ----------

# 台灣常見的姓氏：「陳老師」「林小姐」這類 2～4 個字、姓氏開頭的寄件者名稱，看起來像人名，不送給 AI
COMMON_SURNAMES = set(
    "陳林黃張李王吳劉蔡楊許鄭謝郭洪曾邱廖賴周徐蘇葉莊呂江何蕭羅高潘簡朱鍾游彭詹施胡沈余盧梁趙顏柯翁魏孫戴"
    "范方宋鄧杜傅侯曹薛丁卓阮馬董溫唐藍蔣石古紀姚連馮歐程湯田康姜汪白鄒尤巫鐘黎涂龔嚴韓袁金童陸夏柳邵錢"
    "伍倪于譚駱熊任甘秦顧毛章史官萬俞雷饒闕凌崔尹孔辛武辜陶段龍韋葛池孟褚殷麥賀賈莫文管關向包丘梅華裴利翟")


def safe_sender_name(name):
    """去掉 email、「某某 via LinkedIn」裡的人名；看起來像人名或含敏感資料的，整個不送。"""
    name = guard.EMAIL.sub("", name or "")
    name = re.sub(r"(?i)^.*\bvia\s+", "", name).strip(" \"'<>()[]")[:40]
    if re.fullmatch(r"[一-鿿]{2,4}", name) and name[0] in COMMON_SURNAMES:
        return ""
    return "" if guard.find_sensitive(name) else name


# ---------- AI-0：Gmail 候選清單（是不是帳號、還有沒有在用） ----------

SENDER_KINDS = ("帳號", "電子報", "不是帳號", "不確定")

SENDER_INSTRUCTIONS = """\
下面是寄過信給使用者的網站（senders）。每一筆有：網域 domain、寄件者名稱 sender_name、信件數 emails、
最早和最近收到信的日期 first_seen、last_seen、最近一次「登入、安全通知或訂單」信的日期 last_activity（沒有就是空的）、
程式從信件主旨判斷的標籤 hints（註冊、安全通知、訂單、電子報）。今天是 {today}。
請判斷每一個網站：
1. is_account：使用者在這裡有沒有帳號，只能是：帳號、電子報（只是訂閱，可能沒有帳號）、不是帳號（例如通知信、寄件平台）、不確定
2. in_use：如果有帳號，你比較傾向使用者現在還有在用（y）還是沒在用（n）。一定要選一邊，沒把握就用 confidence 表示
3. confidence：你對 in_use 的把握：high、medium、low
4. reason：一句話說明依據（30 字以內，例如「上個月還有登入通知」），沒把握時說明為什麼難判斷
5. site_info：一句話說明這是什麼網站（20 字以內，例如「台灣的電商平台」），認不出來就寫「不確定」
判斷原則：
- last_activity 在一年內，通常還在用
- 論壇、遊戲、社群這類網站平常不寄信，沒有來信不代表沒在用，這種情況 confidence 填 low
- 學校、公司、政府、銀行這類一直會用到的帳號要特別小心，不確定時 confidence 填 low
- 只有電子報、好幾年沒有登入或訂單信，可能已經不用了
- 是不是帳號沒有把握就填「不確定」，不要猜
只輸出 JSON 陣列，每個網站一筆：
[{{"domain": "...", "is_account": "...", "in_use": "...", "confidence": "...", "reason": "...", "site_info": "..."}}]"""


def accept_senders(reply, allowed):
    """逐筆檢查 AI 的判斷：網域、選項都要合法，說明不能提到其他網站、不能太長。"""
    results = {}
    for item in reply or []:
        if not isinstance(item, dict):
            continue
        domain = item.get("domain")
        if (domain in allowed and item.get("is_account") in SENDER_KINDS and item.get("in_use") in ("y", "n", "?")
                and item.get("confidence") in ("high", "medium", "low")
                and _short_ok(item.get("reason"), allowed, 40) and _short_ok(item.get("site_info"), allowed, 30)):
            results[domain] = {key: item[key].strip() for key in
                               ("is_account", "in_use", "confidence", "reason", "site_info")}
    return results


def classify_senders(rows, today, chunk=80):
    """回傳 {網域: AI 的判斷}。AI 不能用、失敗或回覆不合格的網站不會出現在結果裡。"""
    results = {}
    instructions = SENDER_INSTRUCTIONS.format(today=today.isoformat())
    for start in range(0, len(rows), chunk):
        part = rows[start:start + chunk]
        senders = [{"domain": r["domain"], "sender_name": safe_sender_name(r.get("sender_name")),
                    "emails": int(r.get("emails") or 0), "first_seen": r.get("first_seen") or "",
                    "last_seen": r.get("last_seen") or "", "last_activity": r.get("last_activity") or "",
                    "hints": r.get("hints") or ""} for r in part]
        reply = _ask(f"Gmail 候選清單（第 {start // chunk + 1} 批）", instructions, {"senders": senders}, list)
        results.update(accept_senders(reply, {s["domain"] for s in senders}))
    return results


# ---------- 辨認看不懂的網站 ----------

SITE_INSTRUCTIONS = """\
下面是使用者有帳號、但可能不記得是什麼的網站（sites）。每一筆有網域 domain，
有時還有刪帳號資料庫裡的網站名稱 known_name，或寄件者名稱 sender_name。
請用一句話說明每個網站是什麼（20 字以內，例如「日本的線上遊戲平台」），並給把握程度 confidence：high、medium、low。
規則：只根據網域和提供的名稱判斷；認不出來就填 confidence 為 low、what 寫「不確定」，不要編造。
只輸出 JSON 陣列：[{"domain": "...", "what": "...", "confidence": "..."}]"""


def accept_sites(reply, allowed):
    results = {}
    for item in reply or []:
        if (isinstance(item, dict) and item.get("domain") in allowed
                and item.get("confidence") in ("high", "medium", "low") and _short_ok(item.get("what"), allowed, 30)):
            results[item["domain"]] = {"what": item["what"].strip(), "confidence": item["confidence"]}
    return results


def describe_sites(sites, cache_path, chunk=60):
    """sites：[{domain, known_name, sender_name}]。回傳 {網域: {what, confidence}}。
    結果存在 cache_path，同一個網站下次不再問 AI（刪掉這個檔案就會重新判斷）。"""
    cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    todo = [s for s in sites if s["domain"] not in cache]
    added = False
    for start in range(0, len(todo), chunk):
        part = todo[start:start + chunk]
        payload = []
        for s in part:
            item = {"domain": s["domain"]}
            if s.get("known_name"):
                item["known_name"] = s["known_name"][:40]
            name = safe_sender_name(s.get("sender_name"))
            if name:
                item["sender_name"] = name
            payload.append(item)
        accepted = accept_sites(_ask("辨認網站", SITE_INSTRUCTIONS, {"sites": payload}, list),
                                {s["domain"] for s in part})
        cache.update(accepted)
        added = added or bool(accepted)
    if added:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
    return {s["domain"]: cache[s["domain"]] for s in sites if s["domain"] in cache}


# ---------- AI-1：比對 165 高風險賣場（反過來問：AI 只看公開店名） ----------
#
# 不把你的帳號清單交給 AI：AI 只負責把公開的店名翻成網域（存進快取，下次只翻新的店名），
# 和你的帳號比對這一步由程式在你的電腦上做。

GENERIC_WORDS = {"shop", "store", "online", "mall", "official", "taiwan", "www", "com", "net", "buy"}


def _match(shop, domain, confidence, by):
    return {"shop_name": shop["shop_name"], "times": shop.get("times", 0), "last_listed": shop.get("last_listed"),
            "domain": domain, "confidence": confidence, "by": by}


def _rule_match(shops, domains):
    """不用 AI 的比對：店名裡的英文字和網域名稱相同（或夠長而且包含在網域裡）就算配對。中文店名比不出來。"""
    matches = []
    for shop in shops:
        words = [w for w in re.findall(r"[a-z0-9]{3,}", shop["shop_name"].lower()) if w not in GENERIC_WORDS]
        for domain in domains:
            label = domain.split(".")[0]
            if any(w == label or (len(w) >= 5 and w in label) for w in words):
                matches.append(_match(shop, domain, "medium", "規則"))
    return matches


def shop_key(name):
    return re.sub(r"\s+", "", name).casefold()


def translate_payload(shops):
    """送給 AI 的資料：只有店名和編號，沒有任何你的資料。"""
    return {"shops": [{"shop_id": s["shop_id"], "shop_name": s["shop_name"]} for s in shops]}


def accept_translations(reply, by_id):
    """逐筆檢查 AI 的翻譯，網域整理成主網域。回傳 {shop_id: {domains, confidence}}。"""
    results = {}
    for item in reply or []:
        if not isinstance(item, dict) or item.get("shop_id") not in by_id or item.get("confidence") not in ("high", "medium"):
            continue
        raw = item.get("domains") if isinstance(item.get("domains"), list) else []
        domains = sorted({d for d in (normalize_domain(x) for x in raw[:3] if isinstance(x, str)) if d})
        if domains:
            results[item["shop_id"]] = {"domains": domains, "confidence": item["confidence"]}
    return results


def local_matches(shops, translations, domains):
    """在你的電腦上比對：翻譯出來的網域，有沒有在你的帳號清單裡。"""
    matches = []
    for shop in shops:
        entry = translations.get(shop_key(shop["shop_name"])) or {}
        for domain in entry.get("domains", []):
            if domain in domains:
                matches.append(_match(shop, domain, entry["confidence"], "AI"))
    return matches


def match_165(shops, domains, cache_path, chunk=100):
    """回傳 (可能有關的店家, 這次新翻譯的店名數)。AI 不能用時只用快取和規則比對。"""
    if not shops or not domains:
        return [], 0
    cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    todo = [s for s in shops if shop_key(s["shop_name"]) not in cache]
    translated = 0
    for start in range(0, len(todo), chunk):
        part = todo[start:start + chunk]
        reply = _ask("AI-1 店名翻成網域", TRANSLATE_INSTRUCTIONS, translate_payload(part), list)
        if reply is None:
            break  # AI 不能用或回覆不合格：剩下的店名這次不翻，下次再試
        accepted = accept_translations(reply, {s["shop_id"]: s for s in part})
        for shop in part:  # AI 沒列的店名記成「認不出來」，下次不再重問
            entry = accepted.get(shop["shop_id"], {"domains": [], "confidence": None})
            cache[shop_key(shop["shop_name"])] = {**entry, "shop_name": shop["shop_name"]}
        translated += len(part)
    if translated:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
    matches = local_matches(shops, cache, set(domains))
    seen = {(m["shop_name"], m["domain"]) for m in matches}
    matches += [m for m in _rule_match(shops, domains) if (m["shop_name"], m["domain"]) not in seen]
    return matches, translated


# ---------- 仿冒網域判斷：只問「程式在本機抓出來的可疑網站」 ----------

LOOKALIKE_VERDICTS = ("official", "imitation", "unrelated", "unsure")

LOOKALIKE_INSTRUCTIONS = """\
下面是使用者帳號裡，名稱很像某家店官方網域的網站（lookalikes）。每一筆有：
domain（使用者帳號的網址）、official_domain（這家店的官方網域）、shop_name（165 全民防騙網公布的店名）。
請判斷 domain 是：
- official：同一家公司的其他官方網站（例如不同國家的分站、舊網域、官方的付款或會員網站）
- imitation：很可能是仿冒這家店的假網站
- unrelated：只是名字剛好很像，是不相關的另一家公司
- unsure：沒有把握
並用一句話說明理由（30 字以內）。沒有把握就填 unsure，不要猜。
只輸出 JSON 陣列：[{"id": "L1", "verdict": "imitation", "reason": "…"}]"""


def accept_lookalikes(reply, by_id):
    """逐筆檢查 AI 的判斷。回傳 {id: {verdict, reason}}。"""
    results = {}
    for item in reply or []:
        if not isinstance(item, dict) or item.get("id") not in by_id or item.get("verdict") not in LOOKALIKE_VERDICTS:
            continue
        candidate = by_id[item["id"]]
        allowed = {normalize_domain(candidate["domain"]), candidate["official_domain"]}
        if _short_ok(item.get("reason"), allowed, 40):
            results[item["id"]] = {"verdict": item["verdict"], "reason": item["reason"].strip()}
    return results


def check_lookalikes(candidates):
    """candidates 來自 stages/lookalike.py。回傳 {L 編號: AI 的判斷}；AI 不能用時回傳空的。"""
    if not candidates:
        return {}
    items = [{"id": c["id"], "domain": c["host"], "official_domain": c["official_domain"], "shop_name": c["shop_name"]}
             for c in candidates]
    reply = _ask("仿冒網域判斷", LOOKALIKE_INSTRUCTIONS, {"lookalikes": items}, list)
    return accept_lookalikes(reply, {item["id"]: item for item in items})


# ---------- AI-2：排優先順序、寫白話說明 ----------

def prioritize(evidence, known_domains):
    items = [e for e in evidence if e["kind"] in PRIORITIZE_KINDS]
    if not items:
        return {}
    reply = _ask("AI-2 排優先順序", PRIORITIZE_INSTRUCTIONS, {"evidence": items}, list)
    if reply is None:
        return {}
    ids = {e["id"] for e in items}
    overrides = {}
    for item in reply:
        if not isinstance(item, dict):
            continue
        evidence_id, level = item.get("id"), item.get("level")
        reason, action = item.get("reason"), item.get("action")
        if evidence_id in ids and level in LEVELS and _text_ok(reason, known_domains) and _text_ok(action, known_domains):
            overrides[evidence_id] = {"level": level, "reason": reason.strip(), "action": action.strip()}
    print(f"  AI 回覆 {len(reply)} 筆，通過檢查 {len(overrides)} 筆，其餘 {len(items) - len(overrides)} 筆使用規則判斷")
    return overrides


# ---------- AI-3：寫總結 ----------

def _default_summary(counts, top):
    text = (f"這次共盤點 {counts['accounts']} 個帳號：{counts['pwned_passwords']} 組密碼出現在外洩密碼庫、"
            f"{counts['reused_groups']} 組密碼在多個網站重複使用、"
            f"找到 {counts['breaches']} 起和你的帳號有關的已公開外洩事件。")
    if top:
        text += f"最優先要做的是：{top[0]['action']}"
    else:
        text += "目前沒有需要立刻處理的項目，但查不到不代表安全。"
    return text


def summarize(final, counts, known_domains):
    top = [{"id": f["id"], "level": f["level"], "domain": f["domain"], "action": f["action"]}
           for f in final if f["level"] == "red"][:5]
    if not top:
        top = [{"id": f["id"], "level": f["level"], "domain": f["domain"], "action": f["action"]}
               for f in final if f["level"] == "yellow"][:5]
    reply = _ask("AI-3 寫總結", SUMMARY_INSTRUCTIONS, {"counts": counts, "top_findings": top}, dict)
    text = reply.get("summary") if reply else None
    if isinstance(text, str):
        known_ids = {f["id"] for f in final}
        sentences = [s for s in re.split(r"(?<=[。！？\n])", text) if s.strip()]
        kept = [s for s in sentences
                if _text_ok(s, known_domains) and all(i in known_ids for i in EVIDENCE_ID.findall(s))]
        if len(kept) < len(sentences):
            print(f"  總結裡有 {len(sentences) - len(kept)} 句提到資料以外的內容，已刪除")
        if kept:
            return "".join(kept).strip(), True
    return _default_summary(counts, top), False
