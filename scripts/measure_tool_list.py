"""Print the size of each tool definition as an MCP client receives it.

Usage (in the environment where winremote-mcp and this extension are
installed):

    python scripts/measure_tool_list.py [--tools Name1,Name2,...]

It imports upstream in-process, installs the extension and lists tools
through fastmcp's in-memory client. No server is started and no port is
opened for clients: mcp.run is replaced by a function that raises.

The size of a tool is the length in bytes of its compact JSON definition
(the form sent in a tools/list response). "Enabled by default" is the set
upstream enables without --tools, --enable-tier3 or --disable-tier2 (tiers 1
and 2). --tools reports one more set, resolved the way upstream's --tools
option resolves it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tools", default="", help="comma-separated tool names")
    options = parser.parse_args()

    from fastmcp import Client

    from winremote_session_ext import extension, launcher, tools

    W, tiers, auth, security = launcher.import_upstream()

    def refuse(*_args, **_kwargs):
        raise RuntimeError("measure_tool_list.py never starts a server")

    W.mcp.run = refuse
    extension.install(W, tiers, auth, security)

    async def listing():
        async with Client(W.mcp) as client:
            return await client.list_tools()

    sizes = {}
    for tool in asyncio.run(listing()):
        wire = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        sizes[tool.name] = len(json.dumps(wire, separators=(",", ":")).encode("utf-8"))

    def report(label: str, names) -> None:
        names = set(names)
        total = sum(sizes[n] for n in names)
        print(f"{label + ':':42s} {len(names):3d} tools {total:7,d} bytes")

    ours = set(tools.TOOL_NAMES)
    for name in tools.TOOL_NAMES:
        print(f"{name:42s}           {sizes[name]:7,d} bytes")
    default = tiers.resolve_enabled_tools()
    report("extension tools", ours)
    report("upstream tools, registered (all tiers)", set(sizes) - ours)
    report("enabled by default, upstream only", default - ours)
    report("enabled by default, with the extension", default)
    if options.tools:
        chosen = tiers.resolve_enabled_tools(explicit_tools=tiers.parse_tool_csv(options.tools))
        report("--tools set", chosen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
