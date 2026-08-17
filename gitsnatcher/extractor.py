import os
import sys
import time
import random
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter

from .parser import GitParser
from .dumper import GitDumper
from .scanner import SecretScanner
from .ui import Colors, print_banner, log_msg, format_size

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]


class GitSnatcher:
    """Professional .git repository extractor, reconstructor and analyzer."""

    def __init__(self, args):
        self.args = args
        raw_url = args.url.strip()
        if not raw_url.endswith('/'):
            raw_url += '/'
        if not raw_url.endswith('.git/'):
            raw_url += '.git/'

        self.base_url = raw_url
        self.out_dir = os.path.abspath(args.output_dir)
        self.threads = max(1, getattr(args, 'threads', 10))
        self.timeout = getattr(args, 'timeout', 10)
        self.delay = max(0.0, getattr(args, 'delay', 0.0))
        self.max_retries = max(1, getattr(args, 'retries', 3))
        self.verify_ssl = not getattr(args, 'insecure', False)
        self.quiet = getattr(args, 'quiet', False)
        self.auto_restore = getattr(args, 'restore', False)
        self.scan_secrets_flag = getattr(args, 'scan_secrets', False)
        self.dump_history_flag = getattr(args, 'dump_history', False)
        self.random_agent = getattr(args, 'random_agent', False)

        # Proxies
        proxy_str = getattr(args, 'proxy', None)
        self.proxies = {"http": proxy_str, "https": proxy_str} if proxy_str else None

        # Headers & Auth
        self.headers = {
            "User-Agent": random.choice(USER_AGENTS) if self.random_agent else (getattr(args, 'user_agent', None) or USER_AGENTS[0]),
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }

        # Custom headers
        custom_headers = getattr(args, 'headers', None)
        if custom_headers:
            for h in custom_headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.headers[k.strip()] = v.strip()

        # Cookie header
        cookie = getattr(args, 'cookie', None)
        if cookie:
            self.headers['Cookie'] = cookie

        # Basic Auth
        self.auth = None
        auth_arg = getattr(args, 'auth', None)
        if auth_arg:
            if ":" in auth_arg:
                u, p = auth_arg.split(":", 1)
                self.auth = (u, p)
            elif auth_arg.lower().startswith('bearer '):
                self.headers['Authorization'] = auth_arg
            else:
                self.headers['Authorization'] = f"Bearer {auth_arg}"

        # Initialize Session with Connection Pooling
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)
        if self.auth:
            self.session.auth = self.auth

        adapter = HTTPAdapter(
            pool_connections=self.threads * 2,
            pool_maxsize=self.threads * 2,
            max_retries=0  # We handle custom backoff retries ourselves
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # State tracking
        self.downloaded: Set[str] = set()
        self.queue: Set[str] = set()
        self.discovered_objects: Set[str] = set()
        self.branches_found: Set[str] = set()
        self.remotes_found: Dict[str, str] = {}
        self.commits_found: List[str] = []
        self.lock = threading.Lock()

        self.total_extracted = 0
        self.total_bytes = 0
        self.failed_downloads = 0
        self.start_time = time.time()

        self.initial_files = [
            'HEAD', 'config', 'description', 'info/exclude',
            'info/refs', 'info/grafts', 'logs/HEAD',
            'FETCH_HEAD', 'ORIG_HEAD', 'MERGE_HEAD', 'CHERRY_PICK_HEAD',
            'COMMIT_EDITMSG',
            'refs/heads/master', 'refs/heads/main', 'refs/heads/develop',
            'refs/heads/dev', 'refs/heads/staging', 'refs/heads/prod',
            'refs/heads/production', 'refs/heads/release', 'refs/heads/test',
            'logs/refs/heads/master', 'logs/refs/heads/main', 'logs/refs/heads/develop',
            'logs/refs/heads/dev', 'logs/refs/heads/staging',
            'refs/remotes/origin/HEAD', 'refs/remotes/origin/master',
            'refs/remotes/origin/main', 'refs/remotes/origin/develop',
            'logs/refs/remotes/origin/HEAD', 'logs/refs/remotes/origin/master',
            'logs/refs/remotes/origin/main',
            'refs/stash', 'logs/refs/stash',
            'index', 'packed-refs',
            'objects/info/packs', 'objects/info/alternates',
            'objects/info/commit-graph', 'shallow',
        ]

    def print_msg(self, level: str, msg: str):
        """Helper for backward compatibility."""
        log_msg(level, msg, quiet=self.quiet)

    def is_html_or_error(self, data: bytes, path: str) -> bool:
        """Determine if data is a soft-404 error page or HTML block page."""
        if not data:
            return True

        prefix = data[:300].lower()
        if b'<html' in prefix or b'<!doctype' in prefix or b'<head' in prefix:
            return True

        # Loose object validation: git objects in objects/xx/yy MUST be valid zlib
        if path.startswith('objects/') and not path.startswith('objects/info/') and not path.startswith('objects/pack/'):
            # Loose git objects start with zlib header byte 0x78 (usually \x78\x01, \x78\x9c, \x78\xda)
            if not data.startswith(b'\x78'):
                return True
            try:
                zlib.decompress(data)
            except Exception:
                return True

        return False

    def download_file(self, path: str) -> Optional[bytes]:
        """Download a specific path inside .git/ and store it locally."""
        with self.lock:
            if path in self.downloaded:
                return None
            self.downloaded.add(path)

        url = urljoin(self.base_url, path)
        out_path = os.path.join(self.out_dir, path)

        for attempt in range(self.max_retries):
            if attempt > 0:
                backoff = min(2 ** attempt, 8) + random.uniform(0.1, 0.5)
                time.sleep(backoff)

            if self.delay > 0:
                time.sleep(self.delay)

            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )

                if resp.status_code == 429:
                    retry_after = resp.headers.get('Retry-After', '5')
                    try:
                        time.sleep(float(retry_after))
                    except ValueError:
                        time.sleep(5)
                    continue

                if resp.status_code != 200:
                    continue

                data = resp.content
                if not data or self.is_html_or_error(data, path):
                    continue

                # Write to disk
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'wb') as f:
                    f.write(data)

                with self.lock:
                    self.total_extracted += 1
                    self.total_bytes += len(data)
                    elapsed = max(0.1, time.time() - self.start_time)
                    speed = self.total_extracted / elapsed
                    self.print_msg("status", f"Files: {self.total_extracted} | Queue: {len(self.queue)} | Speed: {speed:.1f}/s | {path[:45]}")

                return data

            except requests.exceptions.RequestException:
                continue

        with self.lock:
            self.failed_downloads += 1
        return None

    def get_object_path(self, sha1: str) -> str:
        """Return relative path for loose object sha1 (e.g. objects/ab/cdef...)."""
        return f"objects/{sha1[:2]}/{sha1[2:]}"

    def parse_object(self, data: bytes) -> List[str]:
        """Parse raw object bytes, extract child hashes, and record object metadata."""
        obj_type, hashes = GitParser.parse_object_data(data)
        if obj_type == "commit":
            cinfo = GitParser.parse_commit(data)
            # Find commit sha if possible or record commit
            pass
        return hashes

    def extract_hashes_from_text(self, data: bytes) -> List[str]:
        """Wrapper for hash extraction from text."""
        return GitParser.extract_hashes_from_text(data)

    def parse_index(self, data: bytes) -> List[str]:
        """Wrapper for index parsing."""
        return GitParser.parse_index(data)

    def parse_pack_index(self, data: bytes) -> List[str]:
        """Wrapper for pack index parsing."""
        return GitParser.parse_pack_index(data)

    def parse_packed_refs(self, data: bytes) -> Dict[str, str]:
        """Wrapper for packed refs parsing."""
        return GitParser.parse_packed_refs(data)

    def probe_metadata(self):
        """Phase 1 & 2: Probe repository metadata, branches, config, reflogs, and index."""
        self.print_msg("info", "Phase 1: Probing repository metadata and structure...")

        # 1. Probe HEAD first
        head_data = self.download_file('HEAD')
        default_branch = None
        if head_data:
            head_text = head_data.decode('utf-8', errors='ignore').strip()
            if head_text.startswith('ref: '):
                default_branch = head_text[5:].strip()
                self.branches_found.add(default_branch)
                self.print_msg("info", f"HEAD points to branch: {Colors.BOLD}{default_branch}{Colors.ENDC}")
            elif len(head_text) == 40:
                self.queue.add(head_text)
                self.print_msg("info", f"HEAD is detached commit: {Colors.BOLD}{head_text}{Colors.ENDC}")

        # 2. Probe .git/config early to extract all configured branches and remotes
        config_data = self.download_file('config')
        if config_data:
            cfg_info = GitParser.parse_git_config(config_data)
            self.remotes_found.update(cfg_info["remotes"])
            for b in cfg_info["branches"]:
                self.branches_found.add(f"refs/heads/{b}")
            if cfg_info["remotes"]:
                for r_name, r_url in cfg_info["remotes"].items():
                    self.print_msg("success", f"Discovered Remote: {Colors.BOLD}{r_name}{Colors.ENDC} → {r_url}")

        # Build dynamic list of files to probe
        probe_list = list(self.initial_files)
        if default_branch:
            probe_list.extend([
                default_branch,
                f"logs/{default_branch}",
            ])

        for branch in self.branches_found:
            if branch not in probe_list:
                probe_list.append(branch)
                probe_list.append(f"logs/{branch}")

        # 3. Probe all initial paths
        for path in probe_list:
            if path in self.downloaded:
                continue

            data = self.download_file(path)
            if not data:
                continue

            if path == 'index':
                index_hashes = GitParser.parse_index(data)
                self.queue.update(index_hashes)
                self.print_msg("success", f"Index parsed: {len(index_hashes)} object hashes indexed")
                continue

            if path == 'packed-refs':
                refs = GitParser.parse_packed_refs(data)
                for ref_name, sha1 in refs.items():
                    self.queue.add(sha1)
                    if not ref_name.endswith('^{}'):
                        self.download_file(ref_name)
                self.print_msg("success", f"packed-refs parsed: {len(refs)} references discovered")
                continue

            if path.startswith('logs/'):
                reflog_entries = GitParser.parse_reflog(data)
                for old_sha, new_sha, _ in reflog_entries:
                    if old_sha != "0000000000000000000000000000000000000000":
                        self.queue.add(old_sha)
                    if new_sha != "0000000000000000000000000000000000000000":
                        self.queue.add(new_sha)
                if reflog_entries:
                    self.print_msg("info", f"Reflog {path}: {len(reflog_entries)} historical commits recovered")
                continue

            if path.endswith('.idx'):
                hashes = GitParser.parse_pack_index(data)
                self.queue.update(hashes)
                pack_path = path.replace('.idx', '.pack')
                self.download_file(pack_path)
                self.print_msg("success", f"Pack index {path}: {len(hashes)} objects discovered")
                continue

            if path == 'objects/info/packs':
                try:
                    text = data.decode('utf-8', errors='ignore')
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and line.endswith('.pack'):
                            idx_path = line.replace('.pack', '.idx')
                            full_idx = f"objects/pack/{idx_path}" if '/' not in line else idx_path
                            idx_data = self.download_file(full_idx)
                            if idx_data:
                                hashes = GitParser.parse_pack_index(idx_data)
                                self.queue.update(hashes)
                                self.download_file(full_idx.replace('.idx', '.pack'))
                                self.print_msg("success", f"Pack discovered: {len(hashes)} objects from {full_idx}")
                except Exception:
                    pass
                continue

            # Fallback text hash discovery for other files
            new_hashes = GitParser.extract_hashes_from_text(data)
            self.queue.update(new_hashes)

    def crawl_objects(self):
        """Phase 3: Recursively crawl Git object DAG using thread pool."""
        self.print_msg("info", f"Phase 2: Recursively fetching {len(self.queue)} discovered objects...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while self.queue:
                current_batch = list(self.queue)
                self.queue.clear()

                futures = {}
                for sha1 in current_batch:
                    if len(sha1) != 40:
                        continue
                    obj_path = self.get_object_path(sha1)
                    with self.lock:
                        if obj_path not in self.downloaded:
                            futures[executor.submit(self.download_file, obj_path)] = sha1

                for future in as_completed(futures):
                    sha1 = futures[future]
                    data = future.result()
                    if data:
                        with self.lock:
                            self.discovered_objects.add(sha1)
                        child_hashes = self.parse_object(data)
                        for ch in child_hashes:
                            ch_path = self.get_object_path(ch)
                            with self.lock:
                                if ch_path not in self.downloaded:
                                    self.queue.add(ch)

    def run(self):
        """Execute full GitSnatcher workflow."""
        print_banner(quiet=self.quiet)
        self.print_msg("info", f"Target: {Colors.BOLD}{self.base_url}{Colors.ENDC}")
        self.print_msg("info", f"Output Directory: {Colors.BOLD}{self.out_dir}{Colors.ENDC}")
        self.print_msg("info", f"Concurrency: {self.threads} threads | Timeout: {self.timeout}s | Retries: {self.max_retries}")
        if self.proxies:
            self.print_msg("info", f"Proxy: {self.proxies.get('http')}")
        if not self.verify_ssl:
            self.print_msg("warning", "SSL verification is disabled.")

        os.makedirs(self.out_dir, exist_ok=True)
        print("-" * 65)

        # 1. Probing metadata & index
        self.probe_metadata()

        # 2. Crawl objects
        print("\n" + "-" * 65)
        self.crawl_objects()

        # 3. Post extraction options
        print("\n" + "=" * 65)
        self.print_msg("success", f"Extraction Finished! Saved {self.total_extracted} files ({format_size(self.total_bytes)}).")
        self.print_msg("success", f"Total Git Objects Reconstructed: {len(self.discovered_objects)}")

        # Auto Restore
        if self.auto_restore:
            print("-" * 65)
            self.print_msg("info", "Auto-Restoring working tree / source code...")
            dumper = GitDumper(self.out_dir)
            restored_count = dumper.auto_restore()
            self.print_msg("success", f"Successfully restored {restored_count} project files to: {dumper.worktree_dir}")

        # Secret Scanning
        if self.scan_secrets_flag:
            print("-" * 65)
            self.print_msg("info", "Running security & secret scanner on recovered repository...")
            scanner = SecretScanner(self.out_dir)
            scanner.scan_all_objects()
            scanner.print_report()

        # History Dump
        if self.dump_history_flag:
            self.dump_commit_history()

        print("=" * 65)
        self.print_msg("info", f"Output directory: {self.out_dir}")
        self.print_msg("info", "Tips:")
        self.print_msg("info", f"  1. cd {self.out_dir}")
        self.print_msg("info", "  2. git status")
        self.print_msg("info", "  3. git checkout -f .")
        self.print_msg("info", "  4. git log -n 10 --oneline --graph --all")

    def dump_commit_history(self):
        """Print concise log of recovered commits."""
        print("-" * 65)
        self.print_msg("info", "Recovered Commit Log:")
        objects_dir = os.path.join(self.out_dir, 'objects')
        if not os.path.isdir(objects_dir):
            return

        count = 0
        for root, _, files in os.walk(objects_dir):
            for fname in files:
                obj_sha = os.path.basename(root) + fname
                obj_path = os.path.join(root, fname)
                try:
                    with open(obj_path, 'rb') as f:
                        raw = f.read()
                    dec = zlib.decompress(raw)
                    if dec.startswith(b'commit '):
                        cinfo = GitParser.parse_commit(dec[dec.find(b'\x00')+1:])
                        first_line = (cinfo.message or "").split('\n')[0][:60]
                        print(f"  {Colors.OKCYAN}{obj_sha[:8]}{Colors.ENDC} {Colors.DIM}{cinfo.author or 'Unknown'}{Colors.ENDC} : {first_line}")
                        count += 1
                        if count >= 20:
                            print(f"  ... and more commits.")
                            return
                except Exception:
                    continue
