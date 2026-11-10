"""記住每次健檢的結果，用來做兩件事：

1. 和上次比：哪些問題解決了、哪些是新出現的、哪些還沒處理
2. 標記已處理：外洩事件這類「歷史事實」，換完密碼後重跑還是會出現，
   所以讓你自己標記（python main.py --done B1），之後就不列入燈號

比對用的是不會變的編號 key（stages/findings.py 的 assign_keys），不是報告上的流水號。
紀錄都存在你電腦上的 data/ 資料夾（data/real 或 data/demo），不會交給 AI。
"""
import time
from collections import Counter

from common import load_json, save_json
from stages.findings import DONE_KINDS, LEVELS

DONE_FILE = "done.json"
HISTORY_DIR = "history"
KEEP = 100  # 最多留幾次的紀錄
PASSWORD_KINDS = {"pwned_password", "reused_password", "weak_password"}  # 要有密碼檔才查得出來的問題


# ---------- 標記已處理 ----------

def load_done(out_dir):
    """你標記過已處理的項目：{key: {date, title}}"""
    return load_json(out_dir / DONE_FILE, {})


def mark(out_dir, ids, undo=False):
    """標記（或取消標記）最近一次報告裡的項目。回傳要印給你看的訊息。"""
    final = load_json(out_dir / "final.json")
    if final is None:
        return ["還沒有健檢結果，請先執行一次健檢。"]
    by_id = {f["id"].upper(): f for f in final}
    done, messages = load_done(out_dir), []
    for raw in ids:
        item = by_id.get(raw.strip().upper())
        if not item:
            messages.append(f"[略過] 沒有 {raw} 這個項目（編號以最近一次的報告為準）")
        elif "key" not in item:
            messages.append(f"[略過] {raw}：這份結果是舊版程式產生的，請先重新執行一次健檢")
        elif undo:
            removed = done.pop(item["key"], None)
            messages.append(f"[取消] {item['title']}" if removed else f"[略過] {raw} 本來就沒有標記已處理")
        elif item["kind"] not in DONE_KINDS:
            messages.append(f"[略過] {raw}（{item['title']}）是密碼的問題，不用標記："
                            "換完密碼後重新匯出密碼檔、再跑一次健檢，程式會自己重新檢查，處理好了就會消失")
        else:
            done[item["key"]] = {"date": time.strftime("%Y-%m-%d"), "title": item["title"]}
            messages.append(f"[已處理] {item['title']}")
    save_json(out_dir / DONE_FILE, done)
    return messages


# ---------- 和上次比 ----------

def latest(out_dir):
    """上一次健檢的紀錄：{"generated": 時間, "items": [{key, title, kind, domain, level}]}；沒有就回傳 None。"""
    files = sorted((out_dir / HISTORY_DIR).glob("*.json"))
    return load_json(files[-1]) if files else None


def save(out_dir, final, generated, carry=()):
    """carry：這次沒檢查到、要照上次的樣子留著的項目（沒檢查密碼時的密碼問題），下次有檢查時才比得出差別。"""
    folder = out_dir / HISTORY_DIR
    items = [{k: f.get(k) for k in ("key", "title", "kind", "domain", "level")} for f in final] + list(carry)
    save_json(folder / time.strftime("%Y%m%d-%H%M%S.json"), {"generated": generated, "items": items})
    for old in sorted(folder.glob("*.json"))[:-KEEP]:
        old.unlink()


def compare(previous_items, final, passwords_checked=True):
    """這次（final）和上次（previous_items）差在哪裡。你標記已處理的項目另外算，不算「解決」也不算「還沒處理」。

    passwords_checked=False：這次沒有檢查密碼。上次的密碼問題這次看不到，不能算成「解決了」，另外放在 unchecked。"""
    before = {i["key"]: i for i in previous_items}
    now = {f["key"]: f for f in final}
    unchecked = [] if passwords_checked else [i for i in previous_items
                                              if i["kind"] in PASSWORD_KINDS and i["level"] != "done"]
    for item in unchecked:
        del before[item["key"]]
    was_open = {k for k, i in before.items() if i["level"] != "done"}
    is_open = {k for k, f in now.items() if f["level"] != "done"}
    still = [k for k in now if k in is_open and k in before]  # 上次就有、現在還沒處理（包含你取消標記的）
    return {
        "resolved": [before[k] for k in before if k in was_open and k not in now],   # 上次有、這次檢查不到了
        "marked": [now[k] for k in now if k not in is_open and k in was_open],        # 上次還在，你標記已處理了
        "new": [now[k] for k in now if k in is_open and k not in before],             # 這次才出現
        "changed": [{**now[k], "was": before[k]["level"]} for k in still              # 燈號變了
                    if before[k]["level"] in LEVELS and now[k]["level"] != before[k]["level"]],
        "still": dict(Counter(now[k]["level"] for k in still)),
        "unchecked": unchecked,
    }
