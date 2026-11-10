"""Gmail 候選清單的自動判斷：哪些是帳號、還有沒有在用。

「兩把鑰匙」：規則和 AI 都同意才自動填 y / n；意見不同或沒把握的，標 ★ 交給你確認。
- 規則看信件日期：最近一年還有登入、安全通知或訂單信 → 還在用；
  兩年以上沒收到任何信、三年以上沒有登入或訂單信 → 可能不用了
- AI 看寄件者名稱和網站類型：例如論壇、遊戲網站平常不寄信，沒有來信不代表沒在用
- 自動填 y 比較寬鬆（填錯只是少一個刪除建議），自動填 n 比較嚴格（填錯會建議你刪掉還在用的帳號）
- 規則已經有明確證據「還在用」的網站（最近一年有登入、安全通知或訂單信）直接填 y，不送給 AI：
  這些是你最常用的帳號，AI 的意見也改變不了結果，就沒有必要讓它看到
- 你自己填過的答案永遠優先，重新掃描也不會被蓋掉
"""
import datetime
from collections import Counter

import guard
import llm
from common import parse_date

REVIEW = "★ 請確認"
ACCOUNT_HINTS = ("註冊", "安全通知", "訂單")


def _days_ago(text, today):
    date = parse_date(text)
    return (today - datetime.date.fromisoformat(date)).days if date else None


def rule_in_use(row, today):
    """只看信件日期的判斷。回傳 (y / n / None, 理由)。"""
    activity = _days_ago(row.get("last_activity"), today)
    last = _days_ago(row.get("last_seen"), today)
    if activity is not None and activity <= 365:
        return "y", f"{row['last_activity'][:7]} 還有登入、安全通知或訂單信"
    if (activity is None or activity > 3 * 365) and last is not None and last > 2 * 365:
        return "n", f"{row['last_seen'][:4]} 年之後就沒有收到任何信"
    return None, ""


def _result(still_using, review, suggested, reason):
    return {"still_using": still_using, "review": review, "suggested": suggested, "reason": reason}


def decide(row, ai, today):
    """決定一列要怎麼填。ai 是 AI 對這個網站的判斷，沒有 AI 時是 None。

    回傳 still_using（自動填的答案，空白代表不填）、review（要不要你確認）、suggested、reason。"""
    rule, rule_reason = rule_in_use(row, today)
    has_hint = any(h in (row.get("hints") or "") for h in ACCOUNT_HINTS)
    if ai is None:  # 沒有 AI：只有規則一把鑰匙，只敢自動填有明確證據的 y
        if rule == "y":
            return _result("y", "", "y", rule_reason + "（規則）")
        if row.get("likely_account") in ("高", "中") or rule == "n":
            return _result("", REVIEW, rule or "?", rule_reason or "有註冊或訂單紀錄，但看不出還有沒有在用")
        return _result("", "", "", "看起來不是帳號（規則）")

    kind, in_use, confidence = ai["is_account"], ai["in_use"], ai["confidence"]
    if kind in ("電子報", "不是帳號") and not has_hint:  # confidence 講的是「還在不在用」，和是不是帳號無關
        return _result("", "", "", ai["reason"])
    if kind == "不確定" and not has_hint and row.get("likely_account") == "低":
        return _result("", "", "", "AI 也不確定，而且沒有註冊、訂單紀錄")
    if kind == "帳號" or has_hint:
        last = _days_ago(row.get("last_seen"), today)
        if rule == "y" and in_use != "n":
            return _result("y", "", "y", rule_reason)
        if in_use == "y" and confidence == "high" and last is not None and last <= 365:
            return _result("y", "", "y", ai["reason"])
        if rule == "n" and in_use == "n" and confidence != "low":
            return _result("n", "", "n", rule_reason)
    return _result("", REVIEW, in_use if in_use in ("y", "n") else "?", ai["reason"] or rule_reason)


def run(rows, backend="auto", model=None, today=None):
    """判斷所有還沒有你答案的列，直接寫回 rows。回傳 (統計, 沒有 AI 時要你確認的數量, 有沒有用到 AI)。"""
    from stages import ai_steps  # 放在這裡，gmail_scan 只有用到這一步時才載入

    today = today or datetime.date.today()
    # 要問 AI 的：你還沒回答、而且規則還不能確定「還在用」的網站
    todo = [r for r in rows if not r.get("decided_by_you") and rule_in_use(r, today)[0] != "y"]
    certain = sum(1 for r in rows if not r.get("decided_by_you")) - len(todo)
    ai_results = {}
    if backend != "none" and todo:
        llm.configure(backend, model)
        if llm.available():
            guard.start_run("Gmail 候選清單")
            print(f"  請 AI 判斷 {len(todo)} 個網站（{llm.describe()}；"
                  "只送網域、寄件者名稱、信件數和日期，不送主旨和內容）…")
            if certain:
                print(f"  另外 {certain} 個最近一年有登入、安全通知或訂單信，規則直接判斷還在用，不送給 AI")
            ai_results = ai_steps.classify_senders(todo, today)
    stats, without_ai = Counter(), 0
    for row in rows:
        if row.get("decided_by_you"):
            row.update(review="", suggested="", reason="你填的")
            stats["你填的"] += 1
            continue
        ai = ai_results.get(row["domain"])
        if ai:
            row["is_account"], row["site_info"] = ai["is_account"], ai["site_info"]
        row.update(decide(row, ai, today))
        without_ai += bool(decide(row, None, today)["review"])
        stats["要你確認" if row["review"] else {"y": "還在用", "n": "不用了"}.get(row["still_using"], "不是帳號")] += 1
    return stats, without_ai, bool(ai_results)
