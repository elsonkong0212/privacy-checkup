"""海關：所有要送給 AI 的資料都必須經過這裡，這是整個程式唯一能呼叫 AI 的入口。

三道關卡：
1. 白名單：只放行指定的欄位，其他欄位（密碼、帳號名稱、email、備註…）直接丟掉
2. 敏感資料偵測：發現疑似身分證字號、信用卡號、email、手機號碼，
   或「你的任何一組密碼」出現在要送出的文字裡，就整批擋下
3. 稽核紀錄：送出去和收回來的每一個字都寫進 audit.log，事後可以檢查

調查模式（--agent）裡 AI 會自己呼叫工具，工具回傳給 AI 的內容也要過前兩關（check_tool_result），
並由 agent_tools.py 寫進 audit.log。
"""
import hashlib
import json
import re
import time

import llm
from common import AUDIT_LOG

ALLOWED_FIELDS = {
    # Gmail 候選清單、辨認看不懂的網站（寄件者名稱送出前會先去掉 email 和疑似人名）
    "senders", "sender_name", "emails", "hints", "last_seen", "last_activity", "sites", "known_name",
    # AI-1：165 店名翻成網域（只送公開的店名）；domains 是 AI-2 證據裡「共用同一組密碼的網站」
    "shops", "shop_id", "shop_name", "domains",
    # 仿冒網域判斷：只送程式在本機抓出來的可疑網站
    "lookalikes", "official_domain",
    # AI-2：排優先順序
    "evidence", "id", "kind", "domain", "pwned_count", "reused", "breach_name", "breach_date",
    "data_classes", "first_seen", "breached_in_group", "confidence", "times", "last_listed", "default_level",
    # AI-3：寫總結
    "counts", "accounts", "breaches", "pwned_passwords", "reused_groups", "red", "yellow", "green",
    "top_findings", "level", "action",
}

# 調查模式：工具回傳給 AI 的欄位（agent_tools.py）
TOOL_FIELDS = ALLOWED_FIELDS | {
    "call_id", "error", "note", "dataset", "findings", "reason", "sources", "still_using",
    "passwords", "strength", "shared_with", "keyword", "total", "matches", "breach_domain", "pwn_count",
    "two_factor_methods", "two_factor_doc", "delete_difficulty", "delete_url",
}

TW_ID = re.compile(r"(?<![A-Za-z0-9])[A-Z][1289]\d{8}(?!\d)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
TW_MOBILE = re.compile(r"(?<!\d)09\d{2}[-\s]?\d{3}[-\s]?\d{3}(?!\d)")
DIGIT_RUN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

stats = {"sent": 0, "blocked": 0}
_secret_hashes = set()


class Blocked(Exception):
    pass


def register_secret_hashes(hashes):
    """記住你每組密碼的雜湊值（不是密碼本身），用來確認沒有任何一組密碼被送出去。"""
    _secret_hashes.update(hashes)


def forget_secret_hashes(hashes):
    _secret_hashes.difference_update(hashes)


def keep_only(data, allowed=ALLOWED_FIELDS):
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


def find_sensitive(text):
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
    if _secret_hashes:
        for token in re.split(r"[\s\"',:{}\[\]]+", text):
            if token and hashlib.sha1(token.encode("utf-8")).hexdigest().upper() in _secret_hashes:
                reasons.append("你的其中一組密碼")
                break
    return reasons


def audit(direction, task, text):
    record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "direction": direction, "task": task, "text": text}
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def start_run(label):
    audit("開始", label, "=== 新的一次執行 ===")


def _prepare(task, instructions, data):
    payload = keep_only(data)                                    # 第 1 關：白名單
    text = instructions + "\n\n資料（JSON）：\n" + json.dumps(payload, ensure_ascii=False, indent=1)
    reasons = find_sensitive(text)                               # 第 2 關：敏感資料偵測
    if reasons:
        stats["blocked"] += 1
        audit("擋下", task, f"原因：{'、'.join(reasons)}（內容不記錄）")
        raise Blocked(f"{task}：偵測到{'、'.join(reasons)}")
    return text


def ask_llm(task, system_prompt, instructions, data):
    """唯一能呼叫 AI 的地方。離線模式下回傳 None（但仍然會過海關、寫紀錄）。"""
    text = _prepare(task, instructions, data)
    if not llm.available():
        audit("離線（未送出）", task, text)                        # 第 3 關：留紀錄
        return None
    audit("送出", task, text)
    stats["sent"] += 1
    reply = llm.complete(system_prompt, text)
    audit("收到", task, reply)
    return reply


def ask_agent(task, system_prompt, instructions, data, data_dir, run_id):
    """調查模式：AI 除了這份資料，還可以呼叫 agent_tools.py 的唯讀工具。工具的每次往返由工具箱記錄。"""
    text = _prepare(task, instructions, data)
    if not llm.available():
        audit("離線（未送出）", task, text)
        return None
    audit("送出", task, text)
    stats["sent"] += 1
    reply = llm.investigate(system_prompt, text, data_dir, run_id)
    audit("收到", task, reply)
    return reply


def check_tool_result(task, result):
    """工具回傳給 AI 的內容也要過海關：只留白名單欄位；有敏感資料就整筆擋下，改回傳錯誤訊息。"""
    payload = keep_only(result, TOOL_FIELDS)
    reasons = find_sensitive(json.dumps(payload, ensure_ascii=False))
    if reasons:
        stats["blocked"] += 1
        audit("擋下", task, f"原因：{'、'.join(reasons)}（內容不記錄）")
        return {"error": f"海關攔截：回傳內容疑似含有{'、'.join(reasons)}，已擋下"}
    return payload
