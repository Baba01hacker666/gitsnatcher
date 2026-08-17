# GitSnatcher

[![Python](https://img.shields.io/badge/Python-3.7%2B-brightgreen.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Made%20by-baba01hacker-blue.svg)](https://github.com/Baba01hacker666)
[![Version](https://img.shields.io/badge/Version-2.0.0-orange.svg)](https://github.com/Baba01hacker666/gitsnatcher)

**GitSnatcher** is a high-performance, professional-grade `.git` directory reconstructor, source code extractor, and intelligence analyzer. It recovers exposed git repositories from web servers, intelligently crawling and decompressing packfiles, index structures, reflogs, and commit DAGs—even when directory listing is disabled, loose objects return 403 Forbidden, or servers employ WAF rate limiting.

---

## Key Features

- ⚡ **Multi-Threaded DAG Crawler:** High-speed recursive crawling across Git objects (commits, trees, blobs, annotated tags) with optimized HTTP connection pooling.
- 🌳 **Deep Index & Extension Parsing:** Full binary support for Git `DIRC` index formats (v2, v3, and v4 prefix compression) plus `TREE` (cached trees) and `REUC` (resolve undo) extension blocks.
- 📦 **Packfile & `.idx` Handling:** Automatically discovers, parses (v1 & v2 index formats), downloads, and unpacks `.pack` files.
- 📜 **Reflog & Branch Discovery:** Automatically enumerates branches, remotes, and submodules from `.git/config` and reconstructs abandoned/historical commits from reflogs (`logs/HEAD`, `logs/refs/heads/*`).
- 🛡️ **Soft-404 & Anti-Corruption Guard:** Strict zlib binary validation on loose objects prevents bogus HTML/JSON 200 OK error pages from polluting the local repository.
- 🔄 **Built-in Source Code Auto-Restore (`-r` / `--restore`):** Pure-Python working tree reconstructor extracts original source code and project files directly into the destination folder—even without `git` installed!
- 🔍 **Security & Secret Scanner (`-s` / `--scan-secrets`):** Integrated audit scanner checks recovered repository objects for leaked API keys, tokens (AWS, OpenAI, GitHub, Stripe, Slack, etc.), database connection strings, RSA private keys, and `.env` files.
- 🕵️ **Evasion & Stealth Engine:** HTTP/HTTPS/SOCKS proxies, custom headers, cookies, randomized browser User-Agents, custom delays, and exponential backoff retry logic.

---

## Installation

### From Source:
```bash
git clone https://github.com/Baba01hacker666/gitsnatcher.git
cd gitsnatcher
pip install .
```

### Quick Run:
```bash
python3 main.py -u http://example.com/.git/ -o ./loot
```

---

## CLI Usage & Options

```bash
gitsnatcher -u <TARGET_URL> -o <OUTPUT_DIR> [OPTIONS]
```

### Full Options Reference

| Option | Short | Description |
| :--- | :--- | :--- |
| `--url` | `-u` | **(Required)** Target `.git` directory URL (e.g. `http://target.com/.git/`) |
| `--output-dir` | `-o` | **(Required)** Local output directory to store the recovered repo |
| `--threads` | `-t` | Number of concurrent download threads (default: `10`) |
| `--delay` | | Delay between requests in seconds (default: `0.0`) |
| `--timeout` | | HTTP request timeout in seconds (default: `10`) |
| `--retries` | | Max retries per failed request (default: `3`) |
| `--proxy` | `-x` | HTTP, HTTPS, or SOCKS proxy (e.g. `http://127.0.0.1:8080`) |
| `--insecure` | `-k` | Disable SSL/TLS certificate verification |
| `--user-agent` | `-A` | Specify a custom User-Agent string |
| `--random-agent` | | Use randomized modern browser User-Agents |
| `--headers` | `-H` | Custom headers (e.g. `-H "Authorization: Bearer token"`) |
| `--cookie` | `-c` | Custom Cookie string (e.g. `-c "session=xyz; admin=1"`) |
| `--auth` | | Basic Auth (`user:pass`) or Bearer Token |
| `--restore` | `-r` | Automatically checkout and restore working tree project files |
| `--scan-secrets` | `-s` | Scan reconstructed objects for leaked credentials & API keys |
| `--dump-history` | | Print concise commit log history of the recovered repo |
| `--quiet` | `-q` | Quiet mode (suppress banners and animations) |
| `--version` | `-v` | Display version information |

---

## Usage Examples

#### 1. Basic Extraction & Auto-Restore
Recover the `.git` repository and automatically extract source files:
```bash
gitsnatcher -u http://target.com/.git/ -o ./loot_dir -r
```

#### 2. Full Intelligence Audit (Extract + Restore + Scan Secrets + History)
```bash
gitsnatcher -u https://target.com/.git/ -o ./loot_dir -t 20 -r -s --dump-history
```

#### 3. Stealth Evasion with Proxy and Randomized User-Agent
```bash
gitsnatcher -u https://target.com/.git/ -o ./loot_dir -x http://127.0.0.1:8080 -k --random-agent --delay 0.2
```

#### 4. Authenticated Extraction
```bash
gitsnatcher -u https://target.com/.git/ -o ./loot_dir -H "Authorization: Bearer mytoken123" -c "session_id=abcdef"
```

---

## Python API Usage

GitSnatcher can also be imported and used programmatically in your own Python tools:

```python
from gitsnatcher import GitParser, GitDumper, SecretScanner

# 1. Parse objects or index files
hashes = GitParser.parse_index(open('.git/index', 'rb').read())
print(f"Discovered {len(hashes)} object hashes from index")

# 2. Extract and restore working tree files
dumper = GitDumper("./recovered_repo/.git")
count = dumper.auto_restore()
print(f"Restored {count} project files")

# 3. Scan for leaked credentials
scanner = SecretScanner("./recovered_repo/.git")
scanner.scan_all_objects()
scanner.print_report()
```

---

## Running Tests

GitSnatcher includes a comprehensive test suite covering all parsers, index v2/v3/v4 extensions, tree unpackers, secret rules, and worktree dumpers:

```bash
python3 -m unittest discover tests
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
