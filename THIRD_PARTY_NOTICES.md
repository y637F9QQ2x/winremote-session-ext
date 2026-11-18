# Third-party notices

## winremote-mcp

- Project: https://github.com/dddabtc/winremote-mcp (maintainer: dddabtc)
- Version this extension was checked against: 0.4.24, from the PyPI wheel
  `winremote_mcp-0.4.24-py3-none-any.whl`
  (SHA-256 `a5d881503baaf01a56e64319709743f3aaa404ecb2b590a483c78dc2072be28d`,
  computed locally from the downloaded file).
- License: MIT, reproduced below.

This repository does not include upstream files. winremote-mcp is installed
separately from PyPI (`requirements.txt`). `src/winremote_session_ext/extension.py`
lists the SHA-256 of three files of that wheel (`winremote/__main__.py`,
`winremote/auth.py`, `winremote/config.py`) to check the installed copy.

One function is derived from upstream code: `patch_auth()` in
`src/winremote_session_ext/extension.py` contains a reimplementation of
`AuthKeyMiddleware.dispatch` from `winremote/auth.py` in winremote-mcp 0.4.24.
It differs from upstream in two ways: the bearer key comparison is
constant-time on bytes, and an empty configured key never matches.

```
MIT License

Copyright (c) 2025 winremote contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Other dependencies (installed by pip, not redistributed here)

The versions the tests in this repository ran with (`constraints.txt` lists
all of them):

| package | version | license | used by this repository for |
|---|---|---|---|
| fastmcp | 4.2.1 | Apache-2.0 | upstream's MCP server; the tests use its in-memory client |
| mcp | 2.3.0 | MIT | MCP types (via upstream) |
| starlette | 1.10.0 | BSD-3-Clause | `Middleware` and `JSONResponse` in `extension.py` |
| click | 8.5.1 | BSD-3-Clause | `ClickException` and `Abort` in `extension.py` and `launcher.py` |
| python-dotenv | 1.2.4 | BSD-3-Clause | `launcher.py` replaces its `load_dotenv()` with a no-op |
| httpx2 | 2.16.2 | BSD-3-Clause | the tests' in-memory HTTP client (installed with upstream) |
| pytest | 9.2.0 | MIT | the tests |

The example client configuration uses mcp-remote (npm, MIT), which is not
installed or redistributed by this repository.
