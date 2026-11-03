# 個人資安健檢（privacy-checkup）

盤點自己的帳號、比對已公開的外洩資料，產生一份「🔴 立刻 / 🟡 這週 / 🟢 有空」的行動清單。
**全程不讓 AI 看到你的密碼。**

- 查密碼、比對外洩事件全部由程式在你的電腦上完成；AI 只負責排優先順序、把結果寫成白話
- Gmail 寄件者由 AI 和規則自動判斷，你只要確認 AI 拿不準的幾個；看不懂的網站也由 AI 辨認
- AI 可以用 Claude、Codex 或 Gemini，也可以完全不用


## 需要準備

- Python 3.10 以上，Windows、macOS、Linux 都可以（主程式只用 Python 內建套件，不用另外安裝）
- 選用：
  - Gmail 寄件者掃描、接上你自己的 AI 工具、AI 調查員：`pip install -r requirements.txt`
  - AI：Claude Code、Codex 或 Gemini API 金鑰其中一種（見「選擇 AI」）；沒有也能跑

## 快速開始（示範資料）

```powershell
git clone <這個專案的網址>
cd privacy-checkup
python main.py --demo --llm none           # 不使用 AI，全部用規則判斷（什麼都不用裝）
python main.py --demo                      # 使用 AI：自動找你電腦上有的 Claude Code、Codex 或 Gemini 金鑰
python main.py --demo --llm codex          # 指定用 Codex（也可以用 --llm claude、--llm gemini）
```

開頭會印出這次用的是哪一種 AI。報告會寫在 `output/report_demo.md`。
每次執行都會先跑 30 個自我測試，全部通過才開始健檢，所以測試通過就代表你的電腦可以用。

> macOS / Linux 的指令是 `python3`；Windows 打 `python` 沒反應的話改用 `py`。

## 完整流程（用自己的資料）

所有個人資料都放在 `privacy-checkup/secrets/`，這個資料夾不會被上傳到 GitHub。程式預設也只讀這裡。

| 步驟 | 做什麼 | 指令或檔案 | 時間 |
|---|---|---|---|
| 0 | 第一次使用：裝套件、Google Cloud 設定 | 見「需要準備」和「Gmail 寄件者掃描」 | 約 20 分鐘，只做一次 |
| 1 | 掃描 Gmail，AI 自動判斷哪些是帳號、還有沒有在用 | `python gmail_scan.py` | 約 5～10 分鐘 |
| 2 | 只確認標 ★ 的列 | `secrets/gmail_candidates.csv` | 幾分鐘 |
| 3 | 補上 Gmail 找不到的帳號 | `secrets/my_accounts.csv` | 約 10 分鐘 |
| 4 | 匯出密碼（跑健檢前再匯出） | `secrets/passwords.csv` | 2 分鐘 |
| 5 | 跑健檢 | `python main.py` | 約 5～10 分鐘 |
| 6 | 看報告，照清單處理 | `output/report.md` | — |

**1. 掃描 Gmail** → 步驟見下一節「Gmail 寄件者掃描」，產生 `secrets/gmail_candidates.csv`

**2. 確認 ★ 的列**
- 打開 `secrets/gmail_candidates.csv`，只看最前面標 ★ 的列，參考 `suggested`、`reason`，在 `still_using` 填 `y` 或 `n`
- 其他列 AI 和規則已經自動填好；看到填錯的直接改


**3. 帳號清單** → 複製 `templates/my_accounts.csv` 到 `secrets/my_accounts.csv`
- 補上 Gmail 掃不到的帳號，例如用 Google、Facebook 登入的網站（到 <https://myaccount.google.com/connections> 看）
- 一行一個網站：`domain`（例如 `shopee.tw`）、`still_using`、`note`（備註，不會交給 AI）
- `still_using` 填 `y`（還在用）、`n`（不用了），或 `?`（**不知道是什麼網站**）
- 填 `n` 的，報告會告訴你怎麼刪；填 `?` 的，報告會請 AI 推測那是什麼網站

**4. 匯出密碼** → 存成 `secrets/passwords.csv`
- Chrome：設定 → 自動填入和密碼 → Google 密碼管理工具 → 設定 → 匯出密碼
- Edge：設定 → 個人資料 → 密碼 → 右上角「⋯」→ 匯出密碼
- 也支援 Firefox、Bitwarden 匯出的 CSV（選單位置可能因版本略有不同）
- 這是明文密碼檔：**跑健檢前再匯出，跑完就刪**，不要另外留備份

**5. 跑健檢**

```powershell
python main.py
```

- 讀取密碼檔前會先問你；跑完會問要不要刪除密碼檔，**請選刪除**
- 不想用 AI：加 `--llm none`

**6. 看報告** → `output/report.md`
- 🔴 立刻處理、🟡 這週處理、🟢 有空再處理：每一項都寫了要做什麼、為什麼、依據是什麼
- 疑似仿冒的網站：你的帳號裡，名稱很像 165 店家官方網站、但其實不是同一個的（例如 `shopee-tw-service.com`）。
  AI 判斷是仿冒的會列成 🔴，提醒你到真正的官方網站改密碼
- ❓ 看不懂的網站：你標 `?` 的網站，AI 推測是什麼、怎麼刪
- 想確認 AI 沒看到密碼：打開 `audit.log`，搜尋你的任何一組密碼，應該找不到

**之後**：換完密碼、刪完帳號後，重新匯出密碼再跑一次 `python main.py`，就能看到處理前後的差別。
重新掃描 Gmail 時，你填過的答案都會保留。

**165 高風險賣場名單**會自動抓取，不用做任何事：
  - AI 只看到公開的店名，負責把店名翻成網域（例如「蝦皮購物」→ `shopee.tw`）；和你的帳號比對在你的電腦上做，**你的帳號清單不會交給 AI**
  - 翻好的結果存在 `data/cache/shop_domains.json`，之後只翻新增的店名
  - 仿冒網域偵測：程式先在本機找出名稱很像這些官方網域的帳號網站，**只有這些可疑的網址**才交給 AI 判斷是官方分站還是仿冒。
    AI 判斷是仿冒的列為 🔴；AI 判斷不是仿冒的不列燈號，但會列在報告的「AI 判斷不是仿冒的網站（請你確認）」，因為 AI 也可能判斷錯
  - 店名要先翻成網域才能比對仿冒網域，所以完全不用 AI（`--llm none`）時，仿冒網域偵測會找不到東西
  - 想補充店名：複製 `templates/165_shops.csv` 到 `secrets/165_shops.csv`，在最後面加一行（只填 `shop_name` 也可以）
  - 離線時加 `--no-165-fetch`，只用手動清單（把 `templates/165_shops.csv` 複製過去就能離線比對）
  - 更新範本裡的快照：`python -m stages.shops165 templates/165_shops.csv`

**選用：holehe**（查你的 email 在哪些國外網站註冊過，**只能查自己的**）

```powershell
pip install holehe
python main.py --email 你的信箱 --holehe
```

## Gmail 寄件者掃描

讀出所有信的**寄件者**，按網站整理成候選清單，再由 AI 和規則**自動判斷**哪些是帳號、還有沒有在用。
你只要看 AI 拿不準、標 ★ 的那幾列。只讀信件標頭，讀不到信件內容。

### 第一次使用：Google Cloud 設定（約 15～20 分鐘，只做一次）

> 介面名稱可能因 Google 改版略有不同。

1. 打開 <https://console.cloud.google.com/>，用**你要掃描的 Gmail 帳號**登入
2. 上方「選取專案」→「新增專案」→ 名稱填 `privacy-checkup` → 建立，並切換到這個專案
3. 啟用 Gmail API：打開 <https://console.cloud.google.com/apis/library/gmail.googleapis.com> → 按「啟用」
4. 左側選單找「**Google Auth Platform**」（舊版介面叫「OAuth 同意畫面」）→「開始」
   - 應用程式名稱：`privacy-checkup`；使用者支援電子郵件：你的 Gmail
   - 目標對象：**外部**
   - 聯絡資訊：你的 Gmail → 勾選同意 → 建立
5. 「**目標對象**」→「測試使用者」→「新增使用者」→ 填你的 Gmail → 儲存
   - 應用程式維持「測試中」就好，**不需要送審**
6. 「**用戶端**」→「建立用戶端」→ 應用程式類型選「**電腦版應用程式**」→ 建立 → **下載 JSON**
7. 把下載的檔案改名成 `gmail_credentials.json`，放進 `secrets/`

### 執行

```powershell
python gmail_scan.py --limit 200   # 先掃最新 200 封試試看
python gmail_scan.py               # 掃整個信箱（1 萬封大約 5 分鐘）
```

1. 瀏覽器會開啟 Google 登入頁。看到「**Google 尚未驗證這個應用程式**」是正常的（這是你自己建的），按「繼續」
2. 權限頁面應該**只**寫「查看電子郵件訊息中繼資料，例如標籤和標頭，但不包括電子郵件內文」。看到其他權限就不要同意
3. 掃完會自動判斷，並印出結果，例如：
   ```
   自動判斷：還在用 25 個、不用了 18 個、不是帳號 60 個（AI＋規則都同意才自動填）
   ★ 要你確認：6 個（已經排在最前面）
   （沒有 AI 的話，要你確認的會是 31 個）
   ```
4. 會問你要不要撤銷授權（建議撤銷）
5. 打開 `secrets/gmail_candidates.csv`（可以用 Excel）：
   - **只要看最前面標 ★ 的列**：參考 `suggested`（AI 傾向的答案）和 `reason`（理由），在 `still_using` 填 `y` 或 `n`
   - 其他列已經自動填好；`site_info` 是 AI 寫的「這是什麼網站」，`is_account` 是 AI 判斷是不是帳號
   - 自動填的答案不對，直接改就好
   - 不是帳號的留空，主程式會忽略；★ 列還沒填，也會先納入健檢

**怎麼自動判斷的（兩把鑰匙）**
- 規則看日期：最近一年還有登入、安全通知或訂單信 → 還在用；兩年以上沒收到信、三年以上沒有登入或訂單信 → 可能不用了
- AI 看寄件者和網站類型：例如論壇、遊戲網站平常不寄信，沒有來信不代表沒在用
- **兩邊都同意才自動填**，意見不同或沒把握的標 ★ 給你確認
- 你填過、改過的答案永遠保留，重新掃描也不會被蓋掉
- 送給 AI 的只有：網域、寄件者名稱、信件數、日期、標籤。主旨和內容不送；看起來像人名的寄件者名稱（例如「陳老師」）也不送
- 不想用 AI：加 `--llm none`，只用規則，要你確認的會比較多
- 已經掃過、想重新判斷（例如換一個 AI）：`python gmail_scan.py --retriage`，不用重新登入 Gmail

掃描別的帳號（例如示範帳號）時加 `--profile`，檔案才不會互相覆蓋：

```powershell
python gmail_scan.py --profile demo --no-browser   # 存成 secrets/gmail_candidates_demo.csv
python main.py --demo --gmail secrets/gmail_candidates_demo.csv
```

`--no-browser` 會印出登入網址，讓你貼到指定的瀏覽器視窗。都處理完後，可以到 Google Cloud 把 `privacy-checkup` 專案刪掉。

## 選擇 AI（`--llm`）

| 選項 | 用的是 | 需要準備 |
|---|---|---|
| `auto`（預設） | 自動找，依序是 Claude Code → Codex → Gemini 金鑰，用第一個**裝好而且登入了**的；都沒有就不用 AI | 不用設定 |
| `claude` | Claude Code CLI | Claude 訂閱。程式會自動找 `claude` 指令或 VS Code 擴充套件內附的執行檔；找不到時設定環境變數 `CLAUDE_BIN` |
| `codex` | OpenAI Codex CLI | ChatGPT 帳號（方案是否包含 Codex 以 OpenAI 公告為準）。安裝：`npm install -g @openai/codex`，再執行一次 `codex login`；也可以用 VS Code 的 Codex 擴充套件內附的執行檔；找不到時設定環境變數 `CODEX_BIN` |
| `gemini` | Google Gemini API | 免費的 API 金鑰（見下方） |
| `none` | 不使用 AI | 不用準備 |

- 自動偵測會跳過裝了但還沒登入的 AI，並印出怎麼登入；第一次呼叫就失敗（例如方案不含 Codex、額度用完）也會自動換下一個再試。成功過一次之後就固定用它，不會中途換
- 用 `--llm` 指定的話就只用那一個，不會自動換；它沒登入時，每一步都會印出「AI 呼叫失敗，改用規則判斷」，報告照樣產生
- 同時有好幾種的話，想用哪一個就用 `--llm` 指定
- `--model` 可以指定模型，例如 `--llm claude --model sonnet`

**申請 Gemini API 金鑰（免費）**
1. 打開 <https://aistudio.google.com/apikey>，用 Google 帳號登入，按「建立 API 金鑰」
2. 把金鑰存成 `secrets/gemini_api_key.txt`（只有一行），或在 PowerShell 設定：`$env:GEMINI_API_KEY="你的金鑰"`
3. 執行 `python main.py --demo --llm gemini`

- 免費方案有次數限制，用完會改用規則判斷，報告照樣產生
- 免費方案送出的內容可能會被 Google 用來改善產品；這個專案送出的只有網域、次數、日期這類資料，介意的話用 `--llm none`

## AI 調查員（實驗功能，預設關閉）

加上 `--agent`，程式做完基本檢查後，會讓 AI 自己用 6 個唯讀工具追查：找名稱不一樣的外洩事件、補查 165 名單、追查紅燈項目的處理方法。
AI 的結論要引用查詢編號，程式檢查過依據才採用。報告最後會多一節「AI 調查紀錄」，列出 AI 查了什麼、採用和刪掉了哪些結論。

- 實測效益低（查 23 次沒有新發現），又會讓 AI 多看到一些資料，所以預設關閉
- 用 Claude 或 Codex 時需要先 `pip install mcp`，沒裝的話會提醒你並自動略過

## 接上你自己的 AI 工具（MCP）

想用平常習慣的 AI 工具聊自己的健檢結果，可以把 `mcp_server.py` 接上去。專案裡已經放好設定檔，
**用 AI 工具打開 `privacy-checkup` 這個資料夾就會自動偵測到**（第一次會問你要不要啟用）：

| 你用的工具 | 設定檔 | 怎麼確認有接上 |
|---|---|---|
| Claude Code | `.mcp.json` | 第一次開啟時選擇允許；輸入 `/mcp` 查看 |
| VS Code + GitHub Copilot | `.vscode/mcp.json` | Copilot 切到 Agent 模式，在工具清單裡找 `privacy-checkup` |
| Cursor | `.cursor/mcp.json` | 設定 → MCP |
| Codex CLI | 不能放在專案裡 | 執行一次：`codex mcp add privacy-checkup -- python "完整路徑\mcp_server.py"` |

1. 先跑完 `python main.py`（或 `--demo`），工具讀的是健檢結果
2. 問 AI，例如：「我的健檢結果哪些要先處理？」「幫我查 bnext 有沒有外洩紀錄」

⚠️ 這些 AI 工具本身能讀你電腦上的檔案：**`secrets/` 裡還有明文密碼檔時，不要開 AI 工具**。

- 設定檔用的指令是 `python`；你的電腦要打 `py` 才能執行 Python 的話，請改設定檔裡的 `command`
- `python mcp_server.py` 是給 AI 工具啟動的，自己在終端機執行會停在那裡等待，按 Ctrl+C 結束

## 所有參數

**`python main.py`**

| 參數 | 用途 |
|---|---|
| `--demo` | 使用 `demo/` 裡的示範資料 |
| `--llm auto/claude/codex/gemini/none` | 選擇 AI（預設 `auto`：自動找電腦上有的） |
| `--agent` | 加上 AI 調查員（實驗功能，預設關閉） |
| `--model 名稱` | 指定模型 |
| `--passwords 檔案` | 密碼檔（預設 `secrets/passwords.csv`） |
| `--manual 檔案` | 帳號清單（預設 `secrets/my_accounts.csv`） |
| `--gmail 檔案` | Gmail 候選清單（預設 `secrets/gmail_candidates.csv`） |
| `--shops 檔案` | 手動補充的 165 店名（預設 `secrets/165_shops.csv`） |
| `--no-165-fetch` | 不自動抓 165 名單，只用手動清單 |
| `--email 信箱 --holehe` | 用 holehe 查自己的 email |
| `--skip-tests` | 略過自我測試（不建議） |

**`python gmail_scan.py`**

| 參數 | 用途 |
|---|---|
| `--limit N` | 只掃最新的 N 封信 |
| `--profile 代號` | 不同帳號的檔案分開存，例如 `demo` |
| `--no-browser` | 不自動開瀏覽器，改成印出登入網址 |
| `--llm auto/claude/codex/gemini/none` | 幫忙判斷的 AI（預設 `auto`）；`none` 只用規則 |
| `--model 名稱` | 指定 AI 模型 |
| `--retriage` | 不重新掃描 Gmail，用現有的候選清單重新判斷 |

**其他**：`python tests/known_answers.py` 可以單獨跑自我測試。
