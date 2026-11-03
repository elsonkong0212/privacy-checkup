"""個人資安健檢 harness。

流程由程式決定，AI 只在固定的地方被呼叫，而且都要經過 guard.py 的海關：

  0. 自我測試 → 1. 密碼檢查 → 2. 帳號盤點 → 3. 外洩比對 → 4. 補救建議
  → AI-1 辨認網站、165 店名翻成網域（比對在本機） →（--agent：AI 調查員用唯讀工具追查）→ AI-2 排優先順序 → AI-3 寫總結 → 報告

用法：
  python main.py --demo                       # 用示範資料
  python main.py                              # 用 secrets/ 裡你自己的資料
  python main.py --llm codex                  # 指定 Codex CLI（預設 auto：自動找電腦上有的 AI；也可以用 gemini）
  python main.py --agent                      # 加上 AI 調查員（實驗功能，實測效益低，預設關閉）
  python main.py --llm none                   # 不使用 AI
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import guard
import llm
from common import BASE, CACHE, DATA, OUTPUT, save_json
from stages import (ai_steps, breach_match, findings, inventory, investigate, lookalike, passwords, remedy, report,
                    shops165)
from tests.known_answers import run_all

DEMO = BASE / "demo"
SECRETS = BASE / "secrets"


def parse_args():
    p = argparse.ArgumentParser(description="個人資安健檢：盤點帳號、比對已公開的外洩資料、產生行動清單。")
    p.add_argument("--demo", action="store_true", help="使用 demo/ 裡的示範資料（簡報示範用）")
    p.add_argument("--passwords", type=Path, help="瀏覽器或密碼管理器匯出的密碼 CSV（預設 secrets/passwords.csv）")
    p.add_argument("--manual", type=Path, help="手動整理的帳號清單（預設 secrets/my_accounts.csv）")
    p.add_argument("--gmail", type=Path,
                   help="gmail_scan.py 產生的候選清單，算填了答案和標 ★ 待確認的帳號（預設 secrets/gmail_candidates.csv）")
    p.add_argument("--shops", type=Path, help="手動補充的 165 高風險賣場店名（預設 secrets/165_shops.csv）")
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
    return p.parse_args()


def ask_yes(question, default):
    try:
        answer = input(f"{question} ({'Y/n' if default else 'y/N'}) ").strip().lower()
    except EOFError:
        return default
    return default if not answer else answer in ("y", "yes", "是")


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

    llm.configure(args.llm, args.model)
    use_agent = args.agent and llm.available()  # 沒有 AI 時調查員自動略過
    if use_agent:
        ready, reason = llm.agent_ready()
        if not ready:
            print(f"[注意] {reason}，這次略過 AI 調查員。")
            use_agent = False
    total = 8 if use_agent else 7

    def step(number, title):
        print(f"\n[{number}/{total}] {title}")

    guard.start_run("示範" if args.demo else "正式")
    print("=== 個人資安健檢 ===")
    print(f"AI：{llm.describe()}" + ("｜含 AI 調查員" if use_agent else "") + ("｜使用示範資料" if args.demo else ""))

    step(0, "自我測試（已知答案測試）")
    if args.skip_tests:
        print("  [注意] 已略過")
    else:
        results = run_all()
        for name, ok, detail in results:
            print(f"  [{'通過' if ok else '失敗'}] {name}：{detail}")
        if not all(ok for _, ok, _ in results):
            sys.exit("\n自我測試沒有全部通過，停止執行。多半是網路連不上，請檢查後再試。")

    step(1, "密碼檢查（純程式，不經過 AI）")
    if not args.passwords.exists():
        sys.exit(f"找不到密碼檔：{args.passwords}\n匯出方式請看 README.md。")
    if not args.demo and not ask_yes(
            f"  即將讀取 {args.passwords}。密碼只在這台電腦上處理，不會交給 AI。繼續嗎？", default=False):
        sys.exit("已取消。")
    pw_summary, secret_hashes, skipped = passwords.run(args.passwords)
    guard.register_secret_hashes(secret_hashes)
    save_json(out_dir / "passwords_summary.json", pw_summary)
    print(f"  檢查了 {len(pw_summary)} 組密碼（略過 {skipped} 筆沒有網址或密碼的資料）")
    print(f"  出現在外洩密碼庫：{sum(1 for s in pw_summary if s['pwned_count'])} 組；"
          f"重複使用：{sum(1 for s in pw_summary if s['reused'])} 組")
    if not args.demo and ask_yes(f"  要刪除 {args.passwords.name} 嗎？這是明文密碼檔，建議刪除", default=True):
        args.passwords.unlink()
        print("  已刪除。")

    step(2, "帳號盤點")
    accounts = inventory.run(pw_summary, args.manual, args.email, args.holehe, args.gmail)
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
    translations = json.loads(path.read_text(encoding="utf-8")) if (path := CACHE / "shop_domains.json").exists() else {}
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

    step(total - 1, "AI-2：排優先順序、寫白話說明")
    known_domains |= {i["official_domain"] for i in lookalike_items}  # AI 的說明可以提到官方網域
    overrides = ai_steps.prioritize(evidence, known_domains)
    final = findings.finalize(evidence, overrides)
    save_json(out_dir / "final.json", final)

    step(total, "AI-3：寫總結，產生報告")
    counts = {
        "accounts": len(accounts),
        "breaches": sum(1 for f in final if f["kind"] == "breach"),
        "pwned_passwords": sum(1 for s in pw_summary if s["pwned_count"]),
        "lookalikes": sum(1 for f in final if f["kind"] == "lookalike_domain"),
        "reused_groups": len({s["reuse_group"] for s in pw_summary if s["reuse_group"]}),
        **{level: sum(1 for f in final if f["level"] == level) for level in findings.LEVELS},
    }
    summary, summary_by_ai = ai_steps.summarize(final, counts, known_domains)
    meta = {
        "generated": time.strftime("%Y-%m-%d %H:%M"), "llm": llm.describe(), "demo": args.demo,
        "breach": breach_meta, "remedy": remedy_meta, "shops165": shop_meta, "guard": dict(guard.stats),
        "skipped": skipped, "investigation": investigation, "site_notes": site_notes, "unknown_sites": unknown_sites,
        "lookalike_cleared": cleared,
    }
    OUTPUT.mkdir(exist_ok=True)
    report_path.write_text(report.render(final, summary, summary_by_ai, counts, meta), encoding="utf-8")

    print(f"\n完成！🔴 {counts['red']}　🟡 {counts['yellow']}　🟢 {counts['green']}")
    print(f"報告：{report_path}")
    print(f"送給 AI {guard.stats['sent']} 次、被海關擋下 {guard.stats['blocked']} 次"
          + (f"；AI 調查員用工具查了 {len(investigation['calls'])} 次" if investigation else "")
          + "，完整紀錄：audit.log")


if __name__ == "__main__":
    main()
