"""把最終結果寫成 Markdown 報告。報告裡的事實都來自程式整理的證據，AI 只負責說明文字。"""
from agent_tools import MAX_CALLS
from stages.findings import DIFFICULTY_ZH, zh_methods

LEVEL_TITLES = {"red": "🔴 立刻處理", "yellow": "🟡 這週處理", "green": "🟢 有空再處理"}
KIND_ORDER = ["pwned_password", "lookalike_domain", "breach", "reused_password", "high_risk_shop", "weak_password",
              "enable_2fa", "delete_account"]
TABLE_KINDS = {"enable_2fa", "delete_account"}  # 綠色的這兩類項目多，用表格呈現
TOOL_ZH = {"list_accounts": "列出帳號", "list_findings": "列出健檢結果", "check_password": "查密碼狀況",
           "search_breaches": "搜尋外洩事件", "search_165": "搜尋 165 名單", "get_remedies": "查補救方法"}


def _sort_key(f):
    return KIND_ORDER.index(f["kind"]), f["domain"]


def _card(f):
    title = f"{f['accounts']} 個帳號共用同一組密碼" if f["kind"] == "reused_password" else f["domain"]
    note = "說明由 AI 撰寫" if f["ai_written"] else "說明由規則產生"
    if f.get("ai_guess"):
        note += "；⚠️ 網站對應是 AI 推測，請自己確認"
    lines = [f"### {f['id']} · {title}", ""]
    if f["kind"] == "reused_password":
        lines.append(f"- **涉及的帳號**：{'、'.join(f['hosts'])}")
    sources = f"；AI 調查依據 {'、'.join(f['investigation_sources'])}" if f.get("investigation_sources") else ""
    lines += [f"- **要做的事**：{f['action']}",
              f"- **原因**：{f['reason']}",
              f"- **依據**：{f['source']}（{note}{sources}）"]
    lines += [f"- **AI 調查補充**：{n['text']}（依據 {'、'.join(n['sources'])}）" for n in f.get("notes", [])]
    if f.get("link"):
        lines.append(f"- **連結**：<{f['link']}>")
    return "\n".join(lines) + "\n"


def _link(f, fallback):
    return "<" + f["link"] + ">" if f.get("link") else fallback


def _what(note):
    """AI 推測的網站說明，把握不高的要講清楚。"""
    if not note or note.get("what") in (None, "", "不確定"):
        return "AI 也認不出來"
    return _cell(note["what"]) + {"medium": "（把握不高）", "low": "（AI 沒把握）"}.get(note.get("confidence"), "")


def _tables(items, site_notes):
    out = []
    tfa = [f for f in items if f["kind"] == "enable_2fa"]
    if tfa:
        out += ["**可以開啟兩步驟驗證的網站**（還沒開的話，有空就開）", "",
                "| 網站 | 支援的方式 | 設定說明 |", "|---|---|---|"]
        out += [f"| {f['domain']} | {zh_methods(f['two_factor_methods'])} | {_link(f, '—')} |" for f in tfa]
        out.append("")
    delete = [f for f in items if f["kind"] == "delete_account"]
    if delete:
        out += ["**你標記為不再使用的帳號**（建議刪除；「這是什麼網站」是 AI 推測）", "",
                "| 網站 | 這是什麼網站 | 刪除難易度 | 刪除方法 |", "|---|---|---|---|"]
        out += [f"| {f['domain']} | {_what(site_notes.get(f['domain']))} | "
                f"{DIFFICULTY_ZH.get(f['delete_difficulty'], '資料庫沒有收錄')} | "
                f"{_link(f, '到帳號設定找，或寫信給客服')} |" for f in delete]
        out.append("")
    return "\n".join(out)


def _unknown_section(sites):
    out = ["## ❓ 看不懂的網站", "",
           "你在清單裡標記 `?` 的網站。AI 只根據網址和網站名稱推測，請自己確認；"
           "確定不用的話就照刪除方法處理，至少確認這個網站的密碼沒有用在別處。", "",
           "| 網站 | AI 推測是什麼 | 刪除難易度 | 刪除方法 |", "|---|---|---|---|"]
    for s in sites:
        difficulty = DIFFICULTY_ZH.get(s.get("delete_difficulty"), "資料庫沒有收錄")
        how = f"<{s['delete_url']}>" if s.get("delete_url") else "到帳號設定找；找不到網站的話，從密碼管理器刪掉這筆就好"
        out.append(f"| {s['domain']} | {_what(s if s.get('what') else None)} | {difficulty} | {how} |")
    return out + [""]


CLEARED_ZH = {"official": "同一家公司的官方網站", "unrelated": "只是名字很像，不相關"}


def _cleared_section(sites):
    out = ["## 🔍 AI 判斷不是仿冒的網站（請你確認）", "",
           "這些網站的名稱很像 165 店家的官方網站，AI 判斷不是仿冒，所以沒有列入上面的燈號。"
           "但 AI 也可能判斷錯，網址又是騙子自己取的：如果你不記得是從官方 App 或官網連過去的，"
           "請當作仿冒處理，不要再登入，並到真正的官方網站改密碼。", "",
           "| 網站 | 很像哪一家 | AI 判斷 | AI 的理由 |", "|---|---|---|---|"]
    for s in sites:
        out.append(f"| {s['host']} | {_cell(s['shop_name'])}（{s['official_domain']}） | "
                   f"{CLEARED_ZH[s['verdict']]} | {_cell(s['reason'])} |")
    return out + [""]


def _shop_source(shop_meta):
    parts = []
    if shop_meta.get("history"):
        parts.append(f"查詢資料 {shop_meta['history'][0]}～{shop_meta['history'][1]}")
    if shop_meta.get("weekly_weeks"):
        parts.append(f"每週公告 {shop_meta['weekly_weeks']} 週")
    if shop_meta.get("manual"):
        parts.append(f"手動補充 {shop_meta['manual']} 家")
    return "165 高風險賣場（" + ("、".join(parts) or "未取得") + "；165 在 2025-10～2026-08 之間沒有發布每週名單）"


def _cell(value):
    """AI 給的查詢字串放進表格前，先處理會破壞表格的字元。"""
    return str(value).replace("|", "\\|").replace("\n", " ")[:80]


def _claim_label(claim):
    if claim.get("type") == "breach":
        return f"{claim.get('domain')} ↔ 外洩事件「{claim.get('breach_name')}」"
    if claim.get("type") == "high_risk_shop":
        return f"{claim.get('domain')} ↔ 165「{claim.get('shop_name')}」"
    return f"{claim.get('id')} 的補充建議"


def _investigation(inv):
    out = ["## AI 調查紀錄", ""]
    if inv["error"]:
        out += [f"⚠️ {inv['error']}，這一步沒有採用任何結論。", ""]
    out.append(f"AI 調查員用唯讀工具查了 {len(inv['calls'])} 次（上限 {MAX_CALLS} 次），提出 {inv['claims']} 個結論："
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


def render(final, summary, summary_by_ai, counts, meta):
    breach_meta, remedy_meta, guard_stats = meta["breach"], meta["remedy"], meta["guard"]
    out = [
        "# 個人資安健檢報告", "",
        f"> 產生時間：{meta['generated']}｜AI：{meta['llm']}" + ("｜⚠️ 這是示範資料" if meta["demo"] else ""), "",
        "## 先看限制", "",
        "- 只能查到**已經被公開**的外洩。查不到 ≠ 安全。",
        f"- HIBP 收錄的 {breach_meta['total']:,} 起外洩事件中，.tw 網域只有 {breach_meta['tw_domains']} 起。"
        "台灣的網站要靠 165 名單和你自己的帳號清單補。",
        "- 信用卡有沒有外洩，工具查不出來：請看帳單、開刷卡即時通知，不放心就請銀行換卡。", "",
        "## 總結", "",
        summary + ("\n\n<sub>（由 AI 撰寫，已檢查只提到資料裡出現的網站）</sub>" if summary_by_ai else ""), "",
        "## 數字", "",
        "| 項目 | 數量 |", "|---|---|",
        f"| 盤點到的帳號 | {counts['accounts']} |",
        f"| 出現在外洩密碼庫的密碼 | {counts['pwned_passwords']} |",
        f"| 疑似仿冒 165 店家的網站 | {counts.get('lookalikes', 0)} |",
        f"| 重複使用的密碼（組） | {counts['reused_groups']} |",
        f"| 和你的帳號有關的已公開外洩事件 | {counts['breaches']} |",
        f"| 🔴 / 🟡 / 🟢 | {counts['red']} / {counts['yellow']} / {counts['green']} |", "",
    ]
    for level in ("red", "yellow", "green"):
        items = sorted((f for f in final if f["level"] == level), key=_sort_key)
        out += [f"## {LEVEL_TITLES[level]}", ""]
        if not items:
            out += ["（沒有）", ""]
            continue
        cards = [f for f in items if not (level == "green" and f["kind"] in TABLE_KINDS)]
        out += [_card(f) for f in cards]
        if level == "green":
            out.append(_tables(items, meta.get("site_notes") or {}))
    if meta.get("unknown_sites"):
        out += _unknown_section(meta["unknown_sites"])
    if meta.get("lookalike_cleared"):
        out += _cleared_section(meta["lookalike_cleared"])
    investigation = meta.get("investigation")
    if investigation:
        out += _investigation(investigation)
    out += [
        "## 這份報告怎麼產生的", "",
        f"- 送給 AI {guard_stats['sent']} 次，全部通過海關（白名單、敏感資料偵測、密碼比對）；"
        f"被海關擋下 {guard_stats['blocked']} 次。送出和收到的完整內容都記在 `audit.log`。",
        "- AI 看得到：網域、外洩次數、外洩日期、外洩的資料種類、網站名稱（刪帳號資料庫的名稱、寄件者名稱；像人名的不送）。"
        "AI 看不到：密碼、帳號名稱、email、你的備註、信件主旨。",
        "- 165 店名對應：AI 只看到公開的店名，負責翻成網域；和你的帳號比對在你的電腦上進行。"
        "仿冒網域偵測也是先在本機比對，只有名稱很像官方網域的可疑網站才交給 AI 判斷；"
        "AI 判斷不是仿冒的也會列出來給你確認，不會悄悄消失。",
        "- AI 可以調整優先順序，但最多只能比規則判斷低一級；網站對應是 AI 推測的項目最多只到 🟡；"
        "AI 的回覆不合格時，改用規則判斷。",
        f"- 資料來源：HIBP 外洩事件清單（{breach_meta['fetched']} 下載）、HIBP Pwned Passwords（即時查詢）、"
        f"2fa.directory（{remedy_meta['2fa_fetched']} 下載）、JustDeleteMe（{remedy_meta['jdm_fetched']} 下載）、"
        f"{_shop_source(meta.get('shops165') or {})}。",
    ]
    if investigation:
        out.append("- AI 調查員只能用 6 個唯讀工具，工具不會回傳密碼、帳號名稱或 email，回傳前也會過海關；"
                   "AI 的每個結論都要引用查詢結果，程式檢查過依據才採用。")
    if meta.get("skipped"):
        out.append(f"- 密碼檔裡有 {meta['skipped']} 筆沒有網址或密碼（例如手機 App 的項目），已略過。")
    return "\n".join(out) + "\n"
