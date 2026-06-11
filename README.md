# GitSnatcher

![GitSnatcher](https://img.shields.io/badge/Made%20by-Baba01hacker666-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-green)

**GitSnatcher** is a professional-grade `.git` directory reconstructor and extractor. It recovers exposed git repositories from web servers, intelligently crawling and decompressing packfiles and index structures even when directory listing is disabled or partial objects return 403 Forbidden.

Made by **Baba01hacker666**.

## Features
- **Smart Reconstruction:** Recursively parses git indexes and tree structures to pull objects dynamically.
- **Multi-Threaded Engine:** Uses thread pooling to download thousands of objects concurrently.
- **Evasion & Proxies:** Native proxy support, SSL verification skipping, custom headers, and rate limiting.
- **Automatic Decompression:** Handles zlib extraction dynamically to find new nested hashes.

## Installation
```bash
pip install gitsnatcher
```
Or from source:
```bash
git clone https://github.com/Baba01hacker666/gitsnatcher.git
cd gitsnatcher
pip install .
```

## Usage
```bash
gitsnatcher -u http://target.com/.git/ -o ./loot_dir
```

### Options
- `-u`, `--url`: Target `.git` URL
- `-o`, `--output-dir`: Where to save the cloned repo locally
- `-t`, `--threads`: Number of threads (default: 10)
- `-x`, `--proxy`: Route traffic through proxy (e.g. `http://127.0.0.1:8080`)
- `-k`, `--insecure`: Disable SSL verification
- `--delay`: Delay between requests

Once downloaded, simply `cd` into the output directory and run `git checkout .` to restore the source code.
