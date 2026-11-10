"""把最終結果寫成 Markdown 報告。報告裡的事實都來自程式整理的證據，AI 只負責說明文字。"""
import guard
from common import normalize_domain
from stages.findings import DIFFICULTY_ZH, zh_methods

LEVEL_TITLES = {"red": "🔴 立刻處理", "yellow": "🟡 這週處理", "green": "🟢 有空再處理"}
KIND_ORDER = ["pwned_password", "lookalike_domain", "breach", "reused_password", "high_risk_shop", "weak_password",
              "enable_2fa", "delete_account"]
TABLE_KINDS = {"enable_2fa", "delete_account"}  # 綠色的這兩類項目多，用表格呈現


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


LEVEL_MARK = {"red": "🔴", "yellow": "🟡", "green": "🟢", "done": "☑️"}
MAX_LISTED = 12  # 「和上次比」每一類最多列幾項，其餘只寫數量


def _listed(items):
    lines = [f"  - {LEVEL_MARK.get(i.get('level'), '')} {_cell(i['title'])}"
             + (f"（上次是 {LEVEL_MARK.get(i['was'], i['was'])}）" if i.get("was") else "") for i in items[:MAX_LISTED]]
    return lines + ([f"  - …還有 {len(items) - MAX_LISTED} 項"] if len(items) > MAX_LISTED else [])


def _changes_section(changes, demo):
    command = "python main.py --demo" if demo else "python main.py"
    out = ["## 和上次比", ""]
    if not changes:
        out += ["這是第一次留下紀錄。下次執行時，這裡會列出哪些問題解決了、哪些是新出現的。", ""]
    else:
        still = changes["still"]
        out += [f"上次健檢：{changes['previous']}。", "",
                f"- ✅ 已經解決（上次有、這次檢查不到了）：{len(changes['resolved'])} 項", *_listed(changes["resolved"]),
                f"- ☑️ 你標記為已處理：{len(changes['marked'])} 項", *_listed(changes["marked"]),
                f"- 🆕 這次新出現：{len(changes['new'])} 項", *_listed(changes["new"])]
        if changes["changed"]:
            out += [f"- 🔁 燈號改變：{len(changes['changed'])} 項", *_listed(changes["changed"])]
        if changes.get("unchecked"):
            out += [f"- ❔ 這次沒有檢查密碼，上次的密碼問題不列入比較（不算解決，也不算還在）：{len(changes['unchecked'])} 項",
                    *_listed(changes["unchecked"])]
        out += [f"- ⏳ 上次就有、還沒處理：🔴 {still.get('red', 0)} 項、🟡 {still.get('yellow', 0)} 項、"
                f"🟢 {still.get('green', 0)} 項", ""]
    out += ["處理完之後，怎麼讓它從清單上消失：",
            "- 密碼的問題（編號 P、R、W）：換完密碼後重新匯出密碼檔、再跑一次健檢，程式會自己重新檢查",
            f"- 其他項目（外洩事件、兩步驟驗證、刪除帳號…）：程式沒辦法知道你處理了沒，請自己標記，"
            f"例如 `{command} --done B1 T2`；標錯了用 `--undo B1` 取消", ""]
    return out


def _done_section(items, demo):
    command = "python main.py --demo" if demo else "python main.py"
    out = ["## ☑️ 你標記為已處理的項目", "",
           f"這些項目不列入上面的燈號。標錯了可以取消，例如 `{command} --undo {items[0]['id']}`。", "",
           "| 編號 | 項目 | 標記日期 |", "|---|---|---|"]
    out += [f"| {f['id']} | {_cell(f['title'])} | {f.get('done_date') or '—'} |" for f in items]
    return out + [""]


def sent_summary(sent_log, account_domains):
    """把海關的送出紀錄（guard.sent_log）整理成每一步送了幾次、裡面有幾個你的帳號網域。
    有哪些步驟、每一步送出什麼，直接照海關登記的內容（guard.TASKS），不另外寫一份。"""
    rows = []
    for task, info in guard.TASKS.items():
        if task == "gmail_senders":  # gmail_scan.py 另外執行，不在這次健檢裡，報告用文字另外說明
            continue
        records = [r for r in sent_log if r["task"] == task]
        if task == "investigate" and not records:  # 實驗功能，沒用到就不列
            continue
        sent = {normalize_domain(d) or d for r in records for d in r["domains"]}
        rows.append({"name": info["name"], "what": info["sends"], "times": len(records),
                     "mine": len(sent & account_domains)})
    return {"rows": rows, "accounts": len(account_domains)}


def _sent_section(ai_sent, use_ai):
    out = ["## 這次送給 AI 的資料", ""]
    if not use_ai:
        return out + ["這次沒有使用 AI，沒有送出任何資料。", ""]
    out += [f"你一共有 {ai_sent['accounts']} 個帳號網域。下面是這次執行每一步實際送出的次數，以及裡面包含幾個你的帳號網域"
            "（完整內容在 `audit.log`）。", "",
            "| 步驟 | 送了幾次 | 送出的內容 | 包含你的帳號網域 |", "|---|---|---|---|"]
    for row in ai_sent["rows"]:
        what = row["what"] if row["times"] else "（這次沒有送出：沿用之前存下來的結果，或沒有需要判斷的項目）"
        out.append(f"| {row['name']} | {row['times']} 次 | {what} | {row['mine']} 個 |")
    out += ["", "密碼、帳號名稱、email、你的備註、信件主旨在任何一步都不會送出。"
            "寫說明和寫總結用的是代號（`[網站1]`），AI 看不到是哪個網站，所以是 0 個；但外洩日期和資料種類還是會送出。"
            "Gmail 寄件者掃描（`gmail_scan.py`）是另外執行的，不在這張表裡：寄過信給你的網站裡，規則還不能確定「還在用」的，"
            "網域、寄件者名稱、信件數和日期都會交給 AI 判斷，範圍比你的帳號清單還大；不想送出就加 `--llm none`，只用規則判斷。", ""]
    return out


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


def render(final, summary, summary_by_ai, counts, meta):
    breach_meta, remedy_meta, guard_stats = meta["breach"], meta["remedy"], meta["guard"]
    no_password = meta.get("no_password_note")  # 這次沒有檢查密碼時的說明；有檢查就是 None
    password_count = (lambda n: "這次沒有檢查") if no_password else str
    out = [
        "# 個人資安健檢報告", "",
        f"> 產生時間：{meta['generated']}｜AI：{meta['llm']}" + ("｜⚠️ 這是示範資料" if meta["demo"] else ""), "",
        "## 先看限制", "",
        "- 只能查到**已經被公開**的外洩。查不到 ≠ 安全。",
        f"- HIBP 收錄的 {breach_meta['total']:,} 起外洩事件中，.tw 網域只有 {breach_meta['tw_domains']} 起。"
        "台灣的網站要靠 165 名單和你自己的帳號清單補。",
        "- 信用卡有沒有外洩，工具查不出來：請看帳單、開刷卡即時通知，不放心就請銀行換卡。",
        *([f"- **{no_password}**。"] if no_password else []), "",
        "## 總結", "",
        summary + ("\n\n<sub>（統計數字由程式計算；「先做什麼」由 AI 撰寫，已檢查只提到資料裡出現的網站和數字）</sub>"
                   if summary_by_ai else ""), "",
        "## 數字", "",
        "| 項目 | 數量 |", "|---|---|",
        f"| 盤點到的帳號 | {counts['accounts']} |",
        f"| 出現在外洩密碼庫的密碼 | {password_count(counts['pwned_passwords'])} |",
        f"| 疑似仿冒 165 店家的網站 | {counts.get('lookalikes', 0)} |",
        f"| 重複使用的密碼（組） | {password_count(counts['reused_groups'])} |",
        f"| 和你的帳號有關的已公開外洩事件 | {counts['breaches']} |",
        f"| 🔴 / 🟡 / 🟢 | {counts['red']} / {counts['yellow']} / {counts['green']} |",
        *([f"| ☑️ 你標記為已處理（不列入燈號） | {counts['done']} |"] if counts.get("done") else []), "",
    ]
    out += _changes_section(meta.get("changes"), meta["demo"])
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
    done_items = sorted((f for f in final if f["level"] == "done"), key=_sort_key)
    if done_items:
        out += _done_section(done_items, meta["demo"])
    investigation = meta.get("investigation")
    if investigation:
        from experimental import investigate  # 實驗功能：有用到 AI 調查員才載入
        out += investigate.report_section(investigation)
    if meta.get("ai_sent"):
        out += _sent_section(meta["ai_sent"], meta.get("use_ai"))
    out += [
        "## 這份報告怎麼產生的", "",
        f"- 送給 AI {guard_stats['sent']} 次，全部通過海關（白名單、敏感資料偵測、密碼比對）；"
        f"被海關擋下 {guard_stats['blocked']} 次。送出和收到的完整內容都記在 `audit.log`。",
        "- AI 看得到：外洩次數、外洩日期、外洩的資料種類；辨認網站和仿冒網域判斷這兩步，另外看得到那幾個網站的網域和名稱"
        "（刪帳號資料庫的名稱、寄件者名稱；像人名的不送）。寫說明和寫總結時，網域、店名、事件名稱都換成代號。"
        "AI 看不到：密碼、帳號名稱、email、你的備註、信件主旨。",
        "- 165 店名對應：用專案內附的店名對照表，表上沒有的新店名才請 AI 翻成網域（AI 只看到公開的店名）；"
        "和你的帳號比對在你的電腦上進行。"
        "仿冒網域偵測也是先在本機比對，只有名稱很像官方網域的可疑網站才交給 AI 判斷；"
        "AI 判斷不是仿冒的也會列出來給你確認，不會悄悄消失。",
        "- 燈號由規則決定，AI 不能調整，只能把說明改寫成白話，所以同一份資料每次跑出來的燈號都一樣"
        "（唯一和 AI 有關的是仿冒網域：AI 判斷是仿冒的列 🔴，這個判斷會存起來沿用）。"
        "網站對應是 AI 推測的項目最多只到 🟡；AI 的回覆不合格時，改用規則寫的說明。",
        "- 總結裡的統計數字由程式計算，不交給 AI；AI 只寫「先做什麼」，寫到資料以外的網站或數字的句子會被刪掉。",
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
