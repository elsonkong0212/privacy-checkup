"""個人資安健檢 harness。

流程由程式決定，AI 只在固定的地方被呼叫，而且都要經過 guard.py 的海關：

  0. 自我測試 → 1. 密碼檢查 → 2. 帳號盤點 → 3. 外洩比對 → 4. 補救建議
  → AI-1 辨認網站、165 店名翻成網域（比對在本機） →（--agent：實驗功能，程式在 experimental/）
  → AI-2 寫白話說明（燈號由規則決定）→ AI-3 寫總結（統計數字由程式寫）→ 報告

用法：
  python main.py --demo                       # 用示範資料
  python main.py                              # 用個人資料資料夾裡你自己的資料（在專案外面，執行時會印出位置）
  python main.py --llm codex                  # 指定 Codex CLI（預設 auto：自動找電腦上有的 AI；也可以用 gemini）
  python main.py --agent                      # 加上 AI 調查員（實驗功能，實測效益低，預設關閉）
  python main.py --llm none                   # 不使用 AI
"""
import argparse
import sys
import time
from collections import Counter
from pathlib import Path

import guard
import llm
from common import BASE, CACHE, DATA, OUTPUT, SECRETS, prepare_secrets, save_json
from stages import (ai_steps, breach_match, findings, history, inventory, lookalike, passwords, remedy, report,
                    shops165)
from tests.known_answers import run_all

DEMO = BASE / "demo"
EXPORT_HELP = ("  Chrome：設定 → 自動填入和密碼 → Google 密碼管理工具 → 設定 → 匯出密碼\n"
               "  Edge：設定 → 個人資料 → 密碼 → 右上角「⋯」→ 匯出密碼（也支援 Firefox、Bitwarden）")
NO_PASSWORD_NOTE = ("這次沒有檢查密碼，其他檢查照常。密碼有沒有外洩、重複，也可以用瀏覽器內建的檢查"
                    "（Chrome：Google 密碼管理工具 → 檢查密碼）")


def parse_args():
    p = argparse.ArgumentParser(
        description="個人資安健檢：盤點帳號、比對已公開的外洩資料、產生行動清單。",
        epilog=f"個人資料資料夾（在專案外面）：{SECRETS}；想換位置就設定環境變數 PRIVACY_CHECKUP_SECRETS。")
    p.add_argument("--demo", action="store_true", help="使用 demo/ 裡的示範資料（簡報示範用）")
    p.add_argument("--passwords", type=Path,
                   help="已經匯出好的密碼 CSV（預設：個人資料資料夾的 passwords.csv）。"
                        "建議不要先匯出：沒有這個檔案時，程式會等你匯出、讀完馬上刪")
    p.add_argument("--no-passwords", action="store_true", help="這次不檢查密碼，也不詢問；其他檢查照常")
    p.add_argument("--manual", type=Path, help="手動整理的帳號清單（預設：個人資料資料夾的 my_accounts.csv）")
    p.add_argument("--gmail", type=Path,
                   help="gmail_scan.py 產生的候選清單，算填了答案和標 ★ 待確認的帳號"
                        "（預設：個人資料資料夾的 gmail_candidates.csv）")
    p.add_argument("--shops", type=Path, help="手動補充的 165 高風險賣場店名（預設：個人資料資料夾的 165_shops.csv）")
    p.add_argument("--no-165-fetch", action="store_true", help="不要自動抓 165 名單，只用手動清單（離線時用）")
    p.add_argument("--email", help="要用 holehe 檢查的 email（只能查自己的）")
    p.add_argument("--holehe", action="store_true", help="執行 holehe（需要另外 pip install holehe）")
    p.add_argument("--llm", choices=llm.CHOICES, default="auto",
                   help="AI 後端：auto = 自動找這台電腦上有的（預設，順序 claude → codex → gemini）；"
                        "claude = Claude Code CLI；codex = Codex CLI；gemini = Gemini API（免費金鑰）；none = 不使用 AI")
    p.add_argument("--agent", action=argparse.BooleanOptionalAction, default=False,
                   help="AI 調查員（實驗功能，預設關閉）：讓 AI 用唯讀工具追查（找別名的外洩事件、165 補查、追查紅燈）")
    p.add_argument("--model", help="指定模型，例如 Claude 的 sonnet；不指定就用預設值")
    p.add_argument("--skip-tests", action="store_true", help="略過自我測試（不建議）")
    p.add_argument("--done", nargs="+", metavar="編號",
                   help="把最近一次報告裡的項目標記成已處理，例如 --done B1 T2（示範資料要加 --demo）；不會執行健檢")
    p.add_argument("--undo", nargs="+", metavar="編號", help="取消已處理的標記，例如 --undo B1；不會執行健檢")
    return p.parse_args()


def ask_yes(question, default, unattended=None):
    """unattended：沒有人可以回答時（例如排程執行）用的答案，不給就和 default 一樣。"""
    try:
        answer = input(f"{question} ({'Y/n' if default else 'y/N'}) ").strip().lower()
    except EOFError:
        return default if unattended is None else unattended
    return default if not answer else answer in ("y", "yes", "是")


def _age(seconds):
    if seconds < 3600:
        return f"{max(seconds, 60) / 60:.0f} 分鐘"
    return f"{seconds / 3600:.0f} 小時" if seconds < 86400 else f"{seconds / 86400:.0f} 天"


def remove_plaintext(path):
    try:
        passwords.destroy(path)
        return True
    except OSError as error:
        print(f"  [注意] 刪不掉 {path}（{error}）。可能被其他程式開著，請關掉後自己刪除。")
        return False


def check_old_exports(expected, can_ask):
    """每次執行都找一下：個人資料資料夾、下載、桌面裡，有沒有以前匯出後忘了刪的密碼檔（明文）。
    只看檔案第一行的欄位名稱來判斷，不會讀到密碼。回傳這幾個資料夾，等一下等你匯出時也是看這裡。"""
    folders = [f for f in dict.fromkeys([expected.parent, Path.home() / "Downloads", Path.home() / "Desktop"])
               if f.is_dir()]
    for folder in folders if can_ask else []:  # 等一下可能要匯出到這些資料夾，先提醒
        if service := passwords.sync_service(folder):
            print(f"  [注意] {folder} 會自動同步到 {service}，存在這裡的密碼檔可能幾秒內就被上傳到雲端。")
    old = [p for p in passwords.find_exports(folders) if not can_ask or p.resolve() != expected.resolve()]
    if old:
        print("  [注意] 發現以前留下的密碼匯出檔（明文），留得越久越危險：")
        for p in old:
            print(f"    {p}（{_age(time.time() - p.stat().st_mtime)}前）")
        if not can_ask:
            print("    用不到的話請刪掉。")
        elif ask_yes("  要現在刪掉嗎？", default=True, unattended=False):  # 沒有人回答時不擅自刪檔
            print(f"  已刪除 {sum(remove_plaintext(p) for p in old)} 個")
    return folders


def read_passwords(args):
    """讀密碼檔並立刻刪掉，盡量縮短明文密碼檔留在硬碟上的時間。
    回傳 (每組密碼的雜湊值和強度, {雜湊值: 長度}, 略過的筆數)；這次不檢查密碼就回傳 None，其他檢查照常。

    建議先不要匯出：程式在這裡等你匯出，檔案一出現就讀取並刪除，只會在硬碟上留幾秒鐘。
    已經匯出好的檔案也能用，但會提醒你它放了多久。"""
    if args.demo:  # 示範用的假密碼：不問、不刪；順便提醒你自己有沒有留下真的匯出檔
        check_old_exports(SECRETS / "passwords.csv", can_ask=False)
        if args.no_passwords:
            return None
        if not args.passwords.exists():
            sys.exit(f"找不到示範密碼檔：{args.passwords}")
        return passwords.read_entries(args.passwords)

    folders = check_old_exports(args.passwords, can_ask=True)
    if args.no_passwords:
        return None

    if args.passwords.exists():
        print(f"  {args.passwords.name} 已經在硬碟上放了 {_age(time.time() - args.passwords.stat().st_mtime)}。"
              "下次可以先不要匯出，讓程式等你匯出，檔案只會留幾秒鐘。")
        if not ask_yes(f"  即將讀取 {args.passwords}。密碼只在這台電腦上處理，不會交給 AI。繼續嗎？", default=False):
            return None
        loaded = passwords.read_entries(args.passwords)
        if ask_yes(f"  已經讀完，接下來只用雜湊值。要刪除 {args.passwords.name} 嗎？這是明文密碼檔，建議刪除", default=True,
                   unattended=False) and remove_plaintext(args.passwords):
            print("  已刪除（先蓋掉內容再刪，不經過資源回收筒）。")
        return loaded

    before = passwords.snapshot(folders)  # 現在已經在的密碼檔不算；之後出現的（匯出、複製貼上、搬過來都算）才是這次的
    print("  沒有密碼檔。要檢查密碼的話，現在匯出就好，程式會等：檔案一出現就讀取並立刻刪除，只會在硬碟上留幾秒鐘。")
    print(EXPORT_HELP)
    print("  存到下面任一個資料夾都可以（直接匯出、或從別的地方複製貼上過來都行），檔名不用改：")
    for folder in folders:
        print(f"    {folder}")
    if not ask_yes("  要現在匯出密碼來檢查嗎？（選 n 就略過密碼檢查，其他項目照常）", default=False):
        return None
    print("  等待匯出中…（最多等 10 分鐘，按 Ctrl+C 取消）")
    try:
        path = passwords.wait_for_export(folders, before)
    except KeyboardInterrupt:
        sys.exit("\n已取消。")
    if not path:
        print("  等了 10 分鐘都沒有看到密碼檔，這次先略過密碼檢查。")
        return None
    found_at = time.time()
    loaded = passwords.read_entries(path)
    if remove_plaintext(path):
        print(f"  讀取 {path.name} 後已刪除：從發現檔案到刪除只經過 {time.time() - found_at:.1f} 秒")
    return loaded


def describe_sites(accounts, remedies):
    """請 AI 說明看不懂的網站（帳號清單填 ? 的）和建議刪除的網站各是什麼。
    Gmail 掃描時 AI 已經寫過說明的直接沿用；其他的參考刪帳號資料庫裡的網站名稱和寄件者名稱。"""
    wanted = [a for a in accounts if a.get("unknown") or a.get("still_using") is False]
    notes = {a["domain"]: {"what": a["site_info"], "confidence": "medium"} for a in wanted if a.get("site_info")}
    names = {r["domain"]: r.get("site_name") for r in remedies}
    notes.update(ai_steps.describe_sites(
        [{"domain": a["domain"], "known_name": names.get(a["domain"]), "sender_name": a.get("sender_name")}
         for a in wanted if a["domain"] not in notes], CACHE / "site_notes.json"))
    removal = {r["domain"]: r for r in remedies}
    unknown = [{"domain": a["domain"], **notes.get(a["domain"], {}),
                "delete_difficulty": removal.get(a["domain"], {}).get("delete_difficulty"),
                "delete_url": removal.get(a["domain"], {}).get("delete_url")}
               for a in accounts if a.get("unknown")]
    if wanted:
        print(f"  辨認網站：你標記看不懂的 {len(unknown)} 個、建議刪除的 {len(wanted) - len(unknown)} 個，"
              f"有說明的 {len(notes)} 個")
    return notes, unknown


def main():
    sys.stdout.reconfigure(errors="replace")  # Windows 終端機顯示不了的字元用 ? 代替，不要當掉
    args = parse_args()
    prepare_secrets()  # 個人資料放在專案外面；舊版留在專案裡 secrets/ 的檔案會搬過去
    # 沒有指定的檔案用預設值；--demo 時預設用 demo/ 的資料（但可以個別換掉，例如換成示範帳號的 Gmail 清單）
    defaults = {"passwords": "fake_passwords.csv", "manual": "manual_accounts.csv",
                "gmail": "gmail_candidates.csv", "shops": "165_shops.csv"} if args.demo else \
               {"passwords": "passwords.csv", "manual": "my_accounts.csv",
                "gmail": "gmail_candidates.csv", "shops": "165_shops.csv"}
    for name, filename in defaults.items():
        if getattr(args, name) is None:
            setattr(args, name, (DEMO if args.demo else SECRETS) / filename)
    out_dir = DATA / ("demo" if args.demo else "real")
    report_path = OUTPUT / ("report_demo.md" if args.demo else "report.md")

    if args.done or args.undo:  # 只標記，不跑健檢
        for message in history.mark(out_dir, args.done or [], undo=False) if args.done else []:
            print(message)
        for message in history.mark(out_dir, args.undo or [], undo=True) if args.undo else []:
            print(message)
        print(f"下次執行 python main.py{' --demo' if args.demo else ''} 時，報告會照這些標記更新。")
        return

    llm.configure(args.llm, args.model)
    use_agent = args.agent and llm.available()  # 沒有 AI 時調查員自動略過
    if use_agent:
        from experimental import agent_llm, investigate  # 實驗功能：有加 --agent 才載入
        ready, reason = agent_llm.ready()
        if not ready:
            print(f"[注意] {reason}，這次略過 AI 調查員。")
            use_agent = False
    total = 8 if use_agent else 7

    def step(number, title):
        print(f"\n[{number}/{total}] {title}")

    guard.start_run("示範" if args.demo else "正式")
    print("=== 個人資安健檢 ===")
    print(f"AI：{llm.describe()}" + ("｜含 AI 調查員" if use_agent else "") + ("｜使用示範資料" if args.demo else ""))
    if not args.demo:
        print(f"個人資料資料夾：{SECRETS}")

    step(0, "自我測試（已知答案測試）")
    if args.skip_tests:
        print("  [注意] 已略過")
    else:
        results = run_all(include_experimental=use_agent)
        for name, ok, detail in results:
            print(f"  [{'通過' if ok else '失敗'}] {name}：{detail}")
        if not all(ok for _, ok, _ in results):
            sys.exit("\n自我測試沒有全部通過，停止執行。多半是網路連不上，請檢查後再試。")

    step(1, "密碼檢查（純程式，不經過 AI；可以略過）")
    loaded = read_passwords(args)  # 密碼檔在這一步就讀完、刪掉；之後連網路查外洩只用雜湊值
    passwords_checked = loaded is not None
    if passwords_checked:
        entries, secret_hashes, skipped = loaded
        guard.register_secret_hashes(secret_hashes)
        pw_summary = passwords.check(entries)
        print(f"  檢查了 {len(pw_summary)} 組密碼（略過 {skipped} 筆沒有網址或密碼的資料）")
        print(f"  出現在外洩密碼庫：{sum(1 for s in pw_summary if s['pwned_count'])} 組；"
              f"重複使用：{sum(1 for s in pw_summary if s['reused'])} 組")
    else:
        pw_summary, skipped = [], 0
        print(f"  {NO_PASSWORD_NOTE}。")
    save_json(out_dir / "passwords_summary.json", pw_summary)

    step(2, "帳號盤點")
    accounts = inventory.run(pw_summary, args.manual, args.email, args.holehe, args.gmail)
    missing = [f"{label}（{path.name}）" for label, path in (("帳號清單", args.manual), ("Gmail 候選清單", args.gmail))
               if not path.exists()]
    if missing:
        print(f"  [注意] 沒有找到 {'、'.join(missing)}，這次沒有納入。要放在：{args.manual.parent}")
    if not accounts:
        sys.exit("\n沒有任何帳號可以檢查。至少要有下面其中一種（做法見 README.md 的「完整流程」）：\n"
                 "  - Gmail 候選清單：python gmail_scan.py\n"
                 f"  - 帳號清單：複製 templates/my_accounts.csv 到 {SECRETS}\n"
                 "  - 密碼檔：重新執行，程式問要不要匯出密碼時選 y\n"
                 "想先看看效果：python main.py --demo")
    save_json(out_dir / "accounts.json", accounts)
    sources = Counter(source for a in accounts for source in a["sources"])
    print(f"  共 {len(accounts)} 個帳號（" + "、".join(f"{s} {n}" for s, n in sources.items()) + "，有重疊）")

    step(3, "外洩比對（HIBP 外洩事件清單）")
    breaches, breach_meta = breach_match.run(accounts)
    save_json(out_dir / "breaches.json", breaches)
    print(f"  HIBP 共收錄 {breach_meta['total']:,} 起外洩事件（其中 .tw 網域 {breach_meta['tw_domains']} 起）")
    print(f"  和你的帳號有關的：{len(breaches)} 起")

    step(4, "補救建議（2fa.directory、JustDeleteMe）")
    remedies, remedy_meta = remedy.run(accounts)
    save_json(out_dir / "remedies.json", remedies)
    print(f"  支援兩步驟驗證的網站：{sum(1 for r in remedies if r['two_factor_methods'])} 個")

    domains = [a["domain"] for a in accounts]
    known_domains = set(domains)

    step(5, "AI-1：辨認網站（165 高風險賣場、仿冒網域、看不懂的網站）")
    site_notes, unknown_sites = describe_sites(accounts, remedies)
    shops, shop_meta = shops165.load(args.shops, fetch=not args.no_165_fetch)
    save_json(out_dir / "shops165.json", [{k: s[k] for k in ("shop_name", "times", "last_listed")} for s in shops])
    if shop_meta["history"]:
        print(f"  自動抓取：查詢資料 {shop_meta['history'][0]}～{shop_meta['history'][1]}、"
              f"每週公告 {shop_meta['weekly_weeks']} 週")
    if shop_meta["manual"]:
        print(f"  手動補充：{shop_meta['manual']} 家（{args.shops.name}）")
    if not shops:
        print("  沒有 165 名單，略過")
    shop_matches, translated = ai_steps.match_165(shops, domains, CACHE / "shop_domains.json")
    if translated:
        print(f"  AI 把 {translated} 個新店名翻成網域（AI 只看到店名，和你的帳號比對在本機進行）")
    print(f"  名單上共 {len(shops)} 家，可能和你的帳號有關的：{len(shop_matches)} 家")

    # 仿冒網域：本機先抓「名稱很像官方網域」的帳號網站，只有這些可疑的才交給 AI 判斷
    translations = ai_steps.load_translations(CACHE / "shop_domains.json")  # 專案內附的對照表＋AI 翻過的新店名
    candidates = lookalike.find_candidates(accounts, pw_summary, translations)
    lookalike_items, cleared = lookalike.build_items(
        candidates, ai_steps.check_lookalikes(candidates, CACHE / "lookalike_verdicts.json"))
    print(f"  仿冒網域偵測：疑似 {len(candidates)} 個"
          + (f"，AI 判斷其中 {len(cleared)} 個是官方分站或不相關（報告會列出來給你確認）" if cleared else "")
          + (f"，列入報告 {len(lookalike_items)} 個" if lookalike_items else ""))

    evidence = findings.build_evidence(pw_summary, accounts, breaches, remedies, shop_matches) + lookalike_items
    save_json(out_dir / "evidence.json", evidence)

    investigation = None
    if use_agent:
        step(6, "AI 調查員：用唯讀工具追查")
        print("  AI 正在查詢，通常要幾分鐘…")
        evidence, investigation = investigate.run(evidence, accounts, out_dir)
        save_json(out_dir / "evidence.json", evidence)
        print(f"  AI 用工具查了 {len(investigation['calls'])} 次；提出 {investigation['claims']} 個發現，"
              f"通過依據檢查 {len(investigation['accepted'])} 個、刪除 {len(investigation['rejected'])} 個")

    step(total - 1, "AI-2：寫白話說明（燈號由規則決定，AI 改不了）")
    known_domains |= {i["official_domain"] for i in lookalike_items}  # AI 的說明可以提到官方網域
    findings.assign_keys(evidence)       # 不會變的編號：用來和上次比、記住你標記已處理的項目
    done = history.load_done(out_dir)    # 你標記已處理的項目不列入燈號，也不用再交給 AI 寫說明
    overrides = ai_steps.explain([e for e in evidence if not findings.marked_done(e, done)], known_domains)
    final = findings.finalize(evidence, overrides, done)
    save_json(out_dir / "final.json", final)

    step(total, "AI-3：寫總結（數字由程式寫，AI 只寫先做什麼），產生報告")
    counts = {
        "accounts": len(accounts),
        "breaches": sum(1 for f in final if f["kind"] == "breach"),
        "pwned_passwords": sum(1 for s in pw_summary if s["pwned_count"]),
        "lookalikes": sum(1 for f in final if f["kind"] == "lookalike_domain"),
        "reused_groups": len({s["reuse_group"] for s in pw_summary if s["reuse_group"]}),
        **{level: sum(1 for f in final if f["level"] == level) for level in (*findings.LEVELS, "done")},
        "passwords_checked": passwords_checked,
    }
    summary, summary_by_ai = ai_steps.summarize(final, counts, known_domains)
    generated = time.strftime("%Y-%m-%d %H:%M")
    previous = history.latest(out_dir)   # 上一次的結果；比完之後把這次的也存起來
    changes = ({"previous": previous["generated"], **history.compare(previous["items"], final, passwords_checked)}
               if previous else None)
    history.save(out_dir, final, generated, carry=changes["unchecked"] if changes else ())
    meta = {
        "generated": generated, "llm": llm.describe(), "demo": args.demo,
        "breach": breach_meta, "remedy": remedy_meta, "shops165": shop_meta, "guard": dict(guard.stats),
        "skipped": skipped, "investigation": investigation, "site_notes": site_notes, "unknown_sites": unknown_sites,
        "lookalike_cleared": cleared, "changes": changes, "no_password_note": None if passwords_checked else NO_PASSWORD_NOTE,
        "ai_sent": report.sent_summary(guard.sent_log, set(domains)), "use_ai": llm.available(),
    }
    OUTPUT.mkdir(exist_ok=True)
    report_path.write_text(report.render(final, summary, summary_by_ai, counts, meta), encoding="utf-8")

    print(f"\n完成！🔴 {counts['red']}　🟡 {counts['yellow']}　🟢 {counts['green']}"
          + (f"　（另有 {counts['done']} 項你已標記處理完）" if counts["done"] else ""))
    if changes:
        print(f"和上次（{changes['previous']}）比：解決 {len(changes['resolved'])} 項、新出現 {len(changes['new'])} 項"
              + (f"、你標記已處理 {len(changes['marked'])} 項" if changes["marked"] else ""))
    print(f"報告：{report_path}")
    print(f"送給 AI {guard.stats['sent']} 次、被海關擋下 {guard.stats['blocked']} 次"
          + (f"；AI 調查員用工具查了 {len(investigation['calls'])} 次" if investigation else "")
          + "，完整紀錄：audit.log")


if __name__ == "__main__":
    main()
