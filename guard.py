"""海關：所有要送給 AI 的資料都必須經過這裡，這是整個程式唯一能呼叫 AI 的入口。

三道關卡：
1. 白名單：每一個工作各有一份（TASKS），只放行那個工作需要的欄位，其他欄位（密碼、帳號名稱、email、備註…）直接丟掉。
   沒有在 TASKS 登記的工作不能呼叫 AI
2. 敏感資料偵測：發現疑似身分證字號、信用卡號、email、手機號碼，
   或「你的任何一組密碼」出現在要送出的文字裡，就整批擋下
   （密碼含空白、逗號、引號也比對得到；10 個字以上的密碼就算夾在一句話中間也擋）
3. 稽核紀錄：送出去和收回來的每一個字都寫進 audit.log，事後可以檢查

實驗功能（experimental/，預設關閉）的 AI 調查員也走同一個入口；它的工具回傳給 AI 的內容
另外要過前兩關（check_tool_result）。
"""
import hashlib
import json
import re
import time

import llm
from common import AUDIT_LOG

# AI-2 看得到的「問題清單」欄位
EVIDENCE_FIELDS = {
    "evidence", "id", "kind", "domain", "default_level",
    "pwned_count", "reused",                                        # 密碼出現在外洩密碼庫
    "domains", "accounts", "breached_in_group",                     # 共用同一組密碼（accounts 是「用在幾個帳號」）
    "breach_name", "breach_date", "data_classes", "first_seen",     # 外洩事件
    "shop_name", "confidence", "times", "last_listed",              # 165 高風險賣場
    "official_domain",                                              # 疑似仿冒網站
}

# 每一個會呼叫 AI 的工作：name 是名稱、sends 是用白話寫的「送出什麼」（報告會照抄）、fields 是白名單。
# 白名單是各自獨立的：例如翻店名那一步只准送店名和編號，就算程式寫錯、把帳號網域一起交過來，也送不出去。
# 想讓 AI 多做一件事，要先在這裡登記。
TASKS = {
    "gmail_senders": {
        "name": "Gmail 寄件者判斷",
        "sends": "規則還不能確定的寄件網站：網域、寄件者名稱（像人名的不送）、信件數、日期、標籤",
        "fields": {"senders", "domain", "sender_name", "emails", "first_seen", "last_seen", "last_activity", "hints"}},
    "describe_sites": {
        "name": "辨認網站",
        "sends": "你標 `?` 的、標記不再使用的網站：網域、網站名稱（刪帳號資料庫的名稱、寄件者名稱）",
        "fields": {"sites", "domain", "known_name", "sender_name"}},
    "translate_shops": {
        "name": "165 店名翻成網域",
        "sends": "165 公布的店名（公開資料，沒有你的資料）；只翻專案內附的對照表沒有的新店名",
        "fields": {"shops", "shop_id", "shop_name"}},
    "lookalikes": {
        "name": "仿冒網域判斷",
        "sends": "名稱很像官方網域的可疑網址，和它像的那家店名、官方網域",
        "fields": {"lookalikes", "id", "domain", "official_domain", "shop_name"}},
    # masked：寫說明不需要知道是哪個網站，所以網域、店名、事件名稱一律換成代號再送；domain 欄位沒換成代號就擋下
    "explain": {
        "name": "寫白話說明",
        "sends": "有問題的項目：外洩次數、外洩日期、外洩的資料種類、最早來信日期（網域、店名、事件名稱都換成代號）",
        "fields": EVIDENCE_FIELDS, "masked": True},
    "summary": {
        "name": "寫總結",
        "sends": "最優先的幾個問題：燈號、要做的事（網域、店名、事件名稱都換成代號）",
        "fields": {"top_findings", "id", "level", "domain", "action"}, "masked": True},
    "investigate": {
        "name": "AI 調查員（--agent）",
        "sends": "全部帳號的網域和問題清單，加上它用工具查到的內容",
        "fields": EVIDENCE_FIELDS},
}

# AI 調查員的工具回傳給 AI 的欄位（experimental/agent_tools.py）
TOOL_FIELDS = EVIDENCE_FIELDS | {
    "call_id", "error", "note", "dataset", "findings", "level", "reason", "action", "sources", "still_using",
    "passwords", "strength", "shared_with", "keyword", "total", "matches", "breach_domain", "pwn_count",
    "two_factor_methods", "two_factor_doc", "delete_difficulty", "delete_url",
}

TW_ID = re.compile(r"(?<![A-Za-z0-9])[A-Z][1289]\d{8}(?!\d)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
TW_MOBILE = re.compile(r"(?<!\d)09\d{2}[-\s]?\d{3}[-\s]?\d{3}(?!\d)")
DIGIT_RUN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

# 密碼比對：把文字切成一段一段時用的幾種切法（只用空白切、照 JSON 的標點切、連 = / ; 這些也切）
SPLITTERS = (re.compile(r"\s+"), re.compile(r"[\s\"',:{}\[\]]+"), re.compile(r"[\s\"',:;=|/\\(){}\[\]<>]+"))
# 這麼長（位元組）以上的密碼，出現在文字的任何位置都擋。更短的不這樣比：
# 像 linkedin 這種密碼會和網址 linkedin.com 撞在一起，把正常的資料全部擋下
MIN_ANYWHERE = 10

stats = {"sent": 0, "blocked": 0}
sent_log = []  # 這次執行每一次送給 AI 的紀錄：{"task": 哪一步, "domains": 送出的資料裡有哪些網域}，報告會列出來
_secrets = {}  # 密碼的雜湊值 → 密碼長度（位元組；不知道長度就是 0）。程式不記密碼本身


class Blocked(Exception):
    pass


def register_secret_hashes(hashes):
    """記住你每組密碼的雜湊值（不是密碼本身），用來確認沒有任何一組密碼被送出去。

    hashes：{雜湊值: 密碼長度}。只給雜湊值的話，就只比對得到「剛好是完整一段」的情況。"""
    lengths = hashes if isinstance(hashes, dict) else dict.fromkeys(hashes, 0)
    _secrets.update({bytes.fromhex(h): length for h, length in lengths.items()})


def forget_secret_hashes(hashes):
    for h in hashes:
        _secrets.pop(bytes.fromhex(h), None)


def keep_only(data, allowed):
    """只留白名單（allowed）上的欄位，不管資料有幾層。"""
    if isinstance(data, dict):
        return {k: keep_only(v, allowed) for k, v in data.items() if k in allowed}
    if isinstance(data, list):
        return [keep_only(v, allowed) for v in data]
    return data


def _luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _strings(data):
    """資料裡所有的文字：欄位名稱和內容。"""
    if isinstance(data, dict):
        for key, value in data.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(data, (list, tuple, set)):
        for value in data:
            yield from _strings(value)
    elif data is not None and not isinstance(data, bool):
        yield str(data)


def _has_secret(text):
    """這段文字裡有沒有你的任何一組密碼？只拿雜湊值比對。

    1. 整段文字，或用空白、標點切開後的任何一段，剛好等於密碼（任何長度的密碼都比）
    2. MIN_ANYWHERE 以上的密碼：出現在任何位置都算，不管前後黏著什麼字、密碼裡有沒有空白或標點"""
    pieces = {text, text.strip()}
    for splitter in SPLITTERS:
        pieces.update(splitter.split(text))
    if any(piece and hashlib.sha1(piece.encode("utf-8", "replace")).digest() in _secrets for piece in pieces):
        return True
    data = text.encode("utf-8", "replace")
    for length in {n for n in _secrets.values() if n >= MIN_ANYWHERE}:
        for start in range(len(data) - length + 1):
            if hashlib.sha1(data[start:start + length]).digest() in _secrets:
                return True
    return False


def find_sensitive(text, data=None):
    """text：要送出去的文字。data：這段文字是從哪份資料轉成 JSON 的（有的話一起給）。

    比對密碼時，除了整段 text，資料裡每個欄位的內容也各自用「原本的樣子」比一次：
    - 某個欄位的內容剛好就是密碼時，不管密碼裡有什麼符號都比對得到
    - 引號、反斜線、換行轉成 JSON 時會被改寫（" 變成 \\"），只看 text 會漏掉"""
    reasons = []
    if TW_ID.search(text):
        reasons.append("疑似身分證字號")
    if EMAIL.search(text):
        reasons.append("email 地址")
    if TW_MOBILE.search(text):
        reasons.append("疑似手機號碼")
    for match in DIGIT_RUN.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            reasons.append("疑似信用卡號")
            break
    if _secrets and any(_has_secret(s) for s in {text, *_strings(data)}):
        reasons.append("你的其中一組密碼")
    return reasons


def audit(direction, task, text):
    record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "direction": direction, "task": task, "text": text}
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def start_run(label):
    audit("開始", label, "=== 新的一次執行 ===")


def _domains_in(data):
    """資料裡 domain、domains 這兩個欄位的內容：用來統計每一步送出了哪些網域。"""
    found = set()
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "domain" and isinstance(value, str):
                found.add(value)
            elif key == "domains" and isinstance(value, list):
                found.update(v for v in value if isinstance(v, str))
            else:
                found |= _domains_in(value)
    elif isinstance(data, list):
        for value in data:
            found |= _domains_in(value)
    return found


# ---------- 代號：AI 不需要知道是哪個網站的工作，名稱換成代號再送，回來再換回去 ----------

PLACEHOLDER = re.compile(r"\[(?:網站|名稱)\d+\]")
MASK_SKIP = {"id", "kind", "level", "default_level", "data_classes", "confidence"}  # 固定的代碼，不是名稱，不換


def make_masks(hide):
    """hide：{"網站": [網域…], "名稱": [店名、事件名稱…]}。回傳 {名稱: 代號}，例如 {"shopee.tw": "[網站1]"}。
    長的名稱排前面先換，短的名稱才不會把長的切掉；太短（不到 3 個字）的不換，免得到處誤換。"""
    masks = {}
    for label, names in (hide or {}).items():
        for number, name in enumerate(sorted({n for n in names if isinstance(n, str) and len(n) >= 3}), 1):
            masks.setdefault(name, f"[{label}{number}]")
    return dict(sorted(masks.items(), key=lambda item: -len(item[0])))


def _mask(data, masks):
    if isinstance(data, dict):
        return {k: v if k in MASK_SKIP else _mask(v, masks) for k, v in data.items()}
    if isinstance(data, list):
        return [_mask(v, masks) for v in data]
    if isinstance(data, str):
        for name, mark in masks.items():
            data = data.replace(name, mark)
    return data


def _unmask(reply, masks):
    """把 AI 回覆裡的代號換回原本的名稱。回覆是 JSON，所以名稱裡的引號、反斜線要照 JSON 的寫法放回去。"""
    for name, mark in masks.items():
        reply = reply.replace(mark, json.dumps(name, ensure_ascii=False)[1:-1])
    return reply


def ask_llm(task, system_prompt, instructions, data, note="", send=None, hide=None):
    """唯一能呼叫 AI 的地方。離線模式下回傳 None（但仍然會過海關、寫紀錄）。

    task：TASKS 裡登記的工作代號，決定用哪一份白名單。note：寫進紀錄的補充（例如「第 2 批」）。
    hide：要換成代號的名稱（見 make_masks）；登記為 masked 的工作一定要換，沒換乾淨就擋下。
    send：實際把文字交給 AI 的函式，預設是 llm.complete（AI 沒有任何工具）；
          實驗功能的 AI 調查員會換成「可以用唯讀工具」的版本，但一樣要先過這裡的三道關卡。"""
    if task not in TASKS:
        raise Blocked(f"「{task}」沒有在海關登記（guard.TASKS），不能呼叫 AI")
    label = TASKS[task]["name"] + note
    masks = make_masks(hide)
    payload = _mask(keep_only(data, TASKS[task]["fields"]), masks)   # 第 1 關：這個工作自己的白名單（再換成代號）
    if TASKS[task].get("masked") and any(not PLACEHOLDER.fullmatch(d) for d in _domains_in(payload)):
        stats["blocked"] += 1
        audit("擋下", label, "原因：這個工作的網域應該全部換成代號，但還有沒換到的（內容不記錄）")
        raise Blocked(f"{label}：網域沒有全部換成代號")
    text = instructions + "\n\n資料（JSON）：\n" + json.dumps(payload, ensure_ascii=False, indent=1)
    reasons = find_sensitive(text, payload)                      # 第 2 關：敏感資料偵測
    if reasons:
        stats["blocked"] += 1
        audit("擋下", label, f"原因：{'、'.join(reasons)}（內容不記錄）")
        raise Blocked(f"{label}：偵測到{'、'.join(reasons)}")
    if not llm.available():
        audit("離線（未送出）", label, text)
        return None
    audit("送出", label, text)                                   # 第 3 關：留紀錄
    stats["sent"] += 1
    sent_log.append({"task": task, "domains": sorted(_domains_in(payload))})
    reply = (send or llm.complete)(system_prompt, text)
    audit("收到", label, reply)                                  # 紀錄的是 AI 真正看到、真正回的內容（代號還沒換回來）
    return _unmask(reply, masks) if isinstance(reply, str) else reply


def check_tool_result(task, result):
    """工具回傳給 AI 的內容也要過海關：只留白名單欄位；有敏感資料就整筆擋下，改回傳錯誤訊息。"""
    payload = keep_only(result, TOOL_FIELDS)
    reasons = find_sensitive(json.dumps(payload, ensure_ascii=False), payload)
    if reasons:
        stats["blocked"] += 1
        audit("擋下", task, f"原因：{'、'.join(reasons)}（內容不記錄）")
        return {"error": f"海關攔截：回傳內容疑似含有{'、'.join(reasons)}，已擋下"}
    return payload
