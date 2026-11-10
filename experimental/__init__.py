"""實驗功能，預設關閉。沒有用到的時候，主程式不會載入這個資料夾裡的任何程式（有自我測試在檢查）。

- AI 調查員（python main.py --agent）：做完基本檢查後，讓 AI 自己用唯讀工具追查
    investigate.py   給 AI 的指示、檢查 AI 的結論有沒有依據、報告裡的「AI 調查紀錄」
    agent_tools.py   AI 能用的 6 個唯讀工具（每次呼叫都編號、過海關、留紀錄）
    agent_llm.py     怎麼讓 Claude Code、Codex、Gemini 用這些工具
    tests.py         這些功能的自我測試（加 --agent 時才跑）
- MCP 工具伺服器（mcp_server.py）：把同一套唯讀工具接到你自己的 AI 工具（Claude Code、Cursor、Copilot…）

放在這裡的原因：實測效益低（在作者的資料上查了 23 次沒有新發現），又會讓 AI 多看到一些資料。
想審查「AI 到底拿得到什麼」的話，先看主程式就好：guard.py、llm.py、stages/ai_steps.py。
"""
