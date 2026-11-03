"""MCP 工具伺服器：把 agent_tools.py 的唯讀工具提供給支援 MCP 的 AI 工具。

兩種用法：
1. python main.py --agent --llm claude（或 codex）：程式會自己啟動這個伺服器，AI 只能用這些工具
2. 接到你自己的 AI 工具（Claude Code、VS Code Copilot、Cursor、Codex…）：
   專案裡的 .mcp.json、.vscode/mcp.json、.cursor/mcp.json 會讓這些工具自動找到它。
   先跑完 python main.py，再問 AI「我的健檢結果哪些要先處理？」

  python mcp_server.py           # 讀 data/real（還沒跑過正式健檢就讀 data/demo）
  python mcp_server.py --demo    # 讀 data/demo
"""
import argparse
import sys
import time
from pathlib import Path
from typing import Annotated

sys.path.insert(0, str(Path(__file__).resolve().parent))  # 從別的資料夾啟動也找得到專案的模組

from pydantic import Field

try:
    from mcp.server.mcpserver import MCPServer  # mcp 2.x
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer  # mcp 1.x
from mcp.types import ToolAnnotations

import agent_tools
from common import DATA

SPECS = agent_tools.SPECS


def _param(tool, name):
    return Field(description=SPECS[tool]["params"][name])


def build_server(box):
    server = MCPServer("privacy-checkup", instructions=agent_tools.SERVER_INSTRUCTIONS)
    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)

    def tool(name):
        return server.tool(name=name, description=SPECS[name]["description"], annotations=read_only)

    @tool("list_accounts")
    def list_accounts() -> dict:
        return box.call("list_accounts")

    @tool("list_findings")
    def list_findings() -> dict:
        return box.call("list_findings")

    @tool("check_password")
    def check_password(domain: Annotated[str, _param("check_password", "domain")]) -> dict:
        return box.call("check_password", {"domain": domain})

    @tool("search_breaches")
    def search_breaches(keyword: Annotated[str, _param("search_breaches", "keyword")]) -> dict:
        return box.call("search_breaches", {"keyword": keyword})

    @tool("search_165")
    def search_165(keyword: Annotated[str, _param("search_165", "keyword")]) -> dict:
        return box.call("search_165", {"keyword": keyword})

    @tool("get_remedies")
    def get_remedies(domain: Annotated[str, _param("get_remedies", "domain")]) -> dict:
        return box.call("get_remedies", {"domain": domain})

    return server


def main():
    p = argparse.ArgumentParser(description="個人資安健檢的 MCP 工具伺服器（唯讀）")
    p.add_argument("--demo", action="store_true", help="讀示範資料 data/demo")
    p.add_argument("--data", type=Path, help="指定資料夾（main.py --agent 使用）")
    p.add_argument("--run", help="這次調查的編號（main.py --agent 使用）")
    p.add_argument("--findings", help="健檢結果的檔名（main.py --agent 使用 evidence.json）")
    args = p.parse_args()
    if args.data:
        data_dir = args.data
    elif args.demo or not (DATA / "real" / "accounts.json").exists():
        data_dir = DATA / "demo"
    else:
        data_dir = DATA / "real"
    box = agent_tools.ToolBox(data_dir, run_id=args.run or time.strftime("chat-%Y%m%d-%H%M%S"),
                              findings_file=args.findings)
    build_server(box).run()


if __name__ == "__main__":
    main()
