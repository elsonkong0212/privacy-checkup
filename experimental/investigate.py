"""AI 調查員（--agent）：程式做完基本檢查之後，讓 AI 用唯讀工具（agent_tools.py）做進一步調查。

AI 可以自己決定查什麼，但每個結論都要附上依據（工具呼叫的編號 T1、T2…），程式會回頭檢查：
- 引用的工具呼叫真的發生過，而且結果裡真的有 AI 說的那筆外洩事件或店名
- 只提到你自己的網站（或查詢結果裡出現的網站）
不合格的結論直接刪掉。通過的新發現會變成新的證據，燈號照樣由規則決定，並標示為 AI 推測。
"""
import json
import time

import guard
from common import normalize_domain
from experimental import agent_llm, agent_tools
from stages import findings
from stages.ai_steps import SYSTEM_PROMPT, _parse_json, _text_ok
from stages.report import _cell

MAX_CLAIMS = 20
MAX_NOTES_PER_ITEM = 2
TOOL_ZH = {"list_accounts": "列出帳號", "list_findings": "列出健檢結果", "check_password": "查密碼狀況",
           "search_breaches": "搜尋外洩事件", "search_165": "搜尋 165 名單", "get_remedies": "查補救方法"}

INSTRUCTIONS = f"""\
你是個人資安健檢的調查員。程式已經做完基本檢查（evidence），你可以用工具做進一步的調查。
工具：list_accounts、list_findings、check_password、search_breaches、search_165、get_remedies。
每次工具回傳都有 call_id（例如 T3）。

請做三件事：
1. 找漏掉的外洩事件：程式只比對「網域完全相同」的外洩事件。對還沒有外洩紀錄的帳號，
   想想這個服務的其他名稱、品牌名、舊網域或母公司，用 search_breaches 搜尋（用英文關鍵字）。
2. 165 補查：對購物、訂票、電商、二手拍賣這類網站，用中文或英文品牌名稱以 search_165 搜尋。
3. 追查紅燈：對 default_level 是 red 的項目，用 check_password、get_remedies 查清楚，
   每個 red 項目都要輸出一筆 type 為 note 的具體處理建議。

規則：
- 工具最多呼叫 {agent_tools.MAX_CALLS - 5} 次。只能根據工具查到的結果下結論，不能用你自己記得的知識當依據。
- 每一筆發現都要附上 sources：支持這筆發現的 call_id。
- domain 只能用資料裡 domains 列出的網域。
- 名稱只有一部分相同（例如都含有 shop）不算同一家；沒有把握就不要列。

最後只輸出 JSON 陣列，不要加其他文字：
[{{"type": "breach", "domain": "使用者的網域", "breach_name": "工具回傳的 breach_name", "reason": "為什麼認為是同一家", "sources": ["T3"]}},
 {{"type": "high_risk_shop", "domain": "使用者的網域", "shop_name": "工具回傳的 shop_name", "reason": "為什麼認為是同一家", "sources": ["T5"]}},
 {{"type": "note", "id": "證據編號，例如 B1", "note": "具體的處理建議，一到三句", "sources": ["T7", "T8"]}}]
沒有任何發現就輸出 []。"""


def _call_summary(record):
    """把一次工具呼叫整理成報告裡的一行。"""
    result = record["result"]
    if "error" in result:
        return result["error"]
    tool = record["tool"]
    if tool in ("search_breaches", "search_165"):
        names = [m.get("breach_name") or m.get("shop_name") for m in result.get("matches", [])]
        return f"{result.get('total', 0)} 筆" + (f"：{'、'.join(names[:3])}" + ("…" if len(names) > 3 else "") if names else "")
    if tool == "check_password":
        if "note" in result:
            return result["note"]
        return "；".join(f"強度{p['strength']}、外洩密碼庫 {p['pwned_count']:,} 次" + ("、和其他網站共用" if p["reused"] else "")
                        for p in result.get("passwords", []))
    if tool == "get_remedies":
        if "two_factor_methods" not in result and "delete_difficulty" not in result:
            return result.get("note", "")
        parts = []
        if "two_factor_methods" in result:
            parts.append(f"兩步驟驗證：{findings.zh_methods(result['two_factor_methods']) or '不支援'}")
        if "delete_difficulty" in result:
            parts.append(f"刪除帳號：{findings.DIFFICULTY_ZH.get(result['delete_difficulty'], result['delete_difficulty'])}")
        return "；".join(parts)
    if tool == "list_accounts":
        return f"{len(result.get('accounts', []))} 個帳號"
    if tool == "list_findings":
        return f"{len(result.get('findings', []))} 個項目"
    return ""


def _next_id(prefix, items):
    numbers = [int(e["id"][len(prefix):]) for e in items if e["id"].startswith(prefix) and e["id"][len(prefix):].isdigit()]
    return f"{prefix}{max(numbers, default=0) + 1}"


def _cited(claim, calls):
    sources = claim.get("sources")
    if not isinstance(sources, list) or not sources:
        return None, "沒有附上依據"
    missing = [str(s) for s in sources if s not in calls]
    if missing:
        return None, f"引用的 {'、'.join(missing)} 不存在"
    return [calls[s] for s in sources], None


def _result_domains(records):
    """查詢結果裡出現的網站：AI 的說明可以提到它們（例如外洩事件的網域）。"""
    found = set()
    for record in records:
        for match in record["result"].get("matches", []):
            domain = normalize_domain(match.get("breach_domain") or "")
            if domain:
                found.add(domain)
    return found


def _text_problem(text, allowed):
    if not isinstance(text, str) or not text.strip():
        return "沒有內容"
    if len(text.strip()) > 300:
        return "太長（超過 300 字）"
    if not _text_ok(text, allowed):
        return "提到清單以外的網站"
    return None


def _check_breach(claim, records, evidence, accounts, allowed):
    domain, name = claim.get("domain"), claim.get("breach_name")
    match = next((m for r in records if r["tool"] == "search_breaches"
                  for m in r["result"].get("matches", []) if m.get("breach_name") == name), None)
    if not match:
        return None, f"引用的查詢結果裡沒有「{name}」這筆外洩事件"
    if any(e["kind"] == "breach" and e["domain"] == domain and e["breach_name"] == name for e in evidence):
        return None, "程式已經找到這筆"
    problem = _text_problem(claim.get("reason"), allowed)
    if problem:
        return None, f"說明{problem}"
    account =next(a for a in accounts if a["domain"] == domain)
    breach = {"domain": domain, "breach_name": name, "breach_date": match["breach_date"],
              "data_classes": match["data_classes"], "pwn_count": match.get("pwn_count"), "verified": None}
    item = findings.build_evidence([], [account], [breach], [], [])[0]  # 燈號和說明沿用規則
    if item["default_level"] == "red":
        item["default_level"] = "yellow"  # AI 推測的對應，最多到 🟡
    item.update(
        ai_guess=True,
        source="HIBP 外洩事件清單（名稱或網址和你的帳號不同，AI 調查推測是同一家，請自己確認）",
        default_reason=f"AI 推測 {domain} 和外洩事件「{name}」是同一家：{claim['reason'].strip().rstrip('。')}。"
                       + item["default_reason"],
    )
    return item, None


def _check_shop(claim, records, evidence):
    domain, name = claim.get("domain"), claim.get("shop_name")
    match = next((m for r in records if r["tool"] == "search_165"
                  for m in r["result"].get("matches", []) if m.get("shop_name") == name), None)
    if not match:
        return None, f"引用的查詢結果裡沒有「{name}」這家店"
    if any(e["kind"] == "high_risk_shop" and e["domain"] == domain and name in e["shop_name"] for e in evidence):
        return None, "程式已經找到這筆"
    item = findings.build_evidence([], [], [], [], [{
        "shop_name": name, "times": match.get("times", 0), "last_listed": match.get("last_listed"),
        "domain": domain, "confidence": "medium", "by": "AI"}])[0]
    item["source"] = "165 高風險賣場名單（AI 調查推測對應，請自己確認）"
    return item, None


def _check_note(claim, records, by_id, allowed):
    target = by_id.get(claim.get("id"))
    if not target:
        return None, f"沒有 {claim.get('id')} 這個項目"
    problem = _text_problem(claim.get("note"), allowed)
    if problem:
        return None, f"建議{problem}"
    related = set(target.get("domains") or [target["domain"]])
    if not any(domain in json.dumps(r, ensure_ascii=False) for r in records for domain in related):
        return None, "引用的查詢和這個項目的網站無關"
    if len(target.get("notes", [])) >= MAX_NOTES_PER_ITEM:
        return None, "這個項目的建議已經夠多了"
    return target, None


def verify(claims, calls, evidence, accounts):
    """逐筆檢查 AI 的結論。回傳 (新的證據, 通過的結論, 被刪掉的結論和原因)。

    「note」類的結論會直接加到原本的證據上（evidence 裡的項目會被修改）。"""
    known_domains = {a["domain"] for a in accounts}
    by_id = {e["id"]: e for e in evidence}
    new_items, accepted, rejected = [], [], []
    for claim in claims[:MAX_CLAIMS]:
        if not isinstance(claim, dict):
            continue
        kind = claim.get("type")
        records, problem = _cited(claim, calls)
        if not problem and kind in ("breach", "high_risk_shop") and claim.get("domain") not in known_domains:
            problem = "不是你的帳號網域"
        if not problem:
            allowed = known_domains | _result_domains(records)
            if kind == "breach":
                item, problem = _check_breach(claim, records, evidence + new_items, accounts, allowed)
            elif kind == "high_risk_shop":
                item, problem = _check_shop(claim, records, evidence + new_items)
            elif kind == "note":
                item, problem = _check_note(claim, records, by_id, allowed)
            else:
                item, problem = None, f"看不懂的類型：{kind}"
        if problem:
            rejected.append({"claim": claim, "problem": problem})
            continue
        if kind == "note":
            item.setdefault("notes", []).append({"text": claim["note"].strip(), "sources": claim["sources"]})
            accepted.append({"claim": claim, "id": item["id"]})
        else:
            prefix = "B" if kind == "breach" else "S"
            item["id"] = _next_id(prefix, evidence + new_items)
            item["investigation_sources"] = claim["sources"]
            new_items.append(item)
            accepted.append({"claim": claim, "id": item["id"]})
    return new_items, accepted, rejected


def run(evidence, accounts, data_dir):
    """回傳 (加上調查結果的證據, 調查紀錄)。AI 不能用或失敗時，證據維持原樣。"""
    run_id = time.strftime("agent-%Y%m%d-%H%M%S")
    log = {"calls": [], "accepted": [], "rejected": [], "claims": 0, "error": None}
    domains = sorted({a["domain"] for a in accounts})
    reply = None
    try:
        # 和其他工作走同一個入口：一樣過白名單、敏感資料偵測、留紀錄，只是把「交給 AI」換成可以用唯讀工具的版本
        reply = guard.ask_llm("investigate", SYSTEM_PROMPT, INSTRUCTIONS, {"domains": domains, "evidence": evidence},
                              send=lambda system, text: agent_llm.investigate(system, text, data_dir, run_id))
    except guard.Blocked as error:
        log["error"] = f"海關攔截：{error}"
    except Exception as error:  # CLI 失敗、逾時、用了不允許的功能
        log["error"] = f"AI 調查失敗：{error}"
    calls = agent_tools.load_calls(data_dir, run_id)
    log["calls"] = [{"call_id": c["call_id"], "tool": c["tool"], "args": c["args"], "summary": _call_summary(c)}
                    for c in calls.values()]
    if log["error"]:
        print(f"  [注意] {log['error']}。這一步略過，報告照樣產生")
        return evidence, log
    if reply is None:
        print("  離線模式，略過")
        return evidence, log
    claims = _parse_json(reply, list)
    if claims is None:
        log["error"] = "AI 回覆的格式不對"
        print(f"  [注意] {log['error']}，這一步略過")
        return evidence, log
    new_items, log["accepted"], log["rejected"] = verify(claims, calls, evidence, accounts)
    log["claims"] = len(log["accepted"]) + len(log["rejected"])
    return evidence + new_items, log


# ---------- 報告裡的「AI 調查紀錄」 ----------

def _claim_label(claim):
    if claim.get("type") == "breach":
        return f"{claim.get('domain')} ↔ 外洩事件「{claim.get('breach_name')}」"
    if claim.get("type") == "high_risk_shop":
        return f"{claim.get('domain')} ↔ 165「{claim.get('shop_name')}」"
    return f"{claim.get('id')} 的補充建議"


def report_section(inv):
    """inv 是 run() 回傳的調查紀錄。回傳報告裡要加的幾行。"""
    out = ["## AI 調查紀錄", ""]
    if inv["error"]:
        out += [f"⚠️ {inv['error']}，這一步沒有採用任何結論。", ""]
    out.append(f"AI 調查員用唯讀工具查了 {len(inv['calls'])} 次（上限 {agent_tools.MAX_CALLS} 次），提出 {inv['claims']} 個結論："
               f"通過依據檢查 {len(inv['accepted'])} 個、刪除 {len(inv['rejected'])} 個。"
               "每次查詢的參數和回傳內容都記在 `audit.log`。")
    if inv["calls"]:
        out += ["", "| 編號 | 工具 | 查詢 | 結果 |", "|---|---|---|---|"]
        out += [f"| {c['call_id']} | {TOOL_ZH.get(c['tool'], _cell(c['tool']))} | "
                f"{_cell('、'.join(map(str, c['args'].values())) or '—')} | {_cell(c['summary'])} |"
                for c in inv["calls"]]
    if inv["accepted"]:
        out += ["", "**採用的結論**：" + "、".join(f"{a['id']}（{_cell(_claim_label(a['claim']))}）"
                                              for a in inv["accepted"])]
    if inv["rejected"]:
        out += ["", "**被刪掉的結論**（沒有依據，或依據對不上）：", ""]
        out += [f"- {_cell(_claim_label(r['claim']))}：{r['problem']}" for r in inv["rejected"]]
    return out + [""]
