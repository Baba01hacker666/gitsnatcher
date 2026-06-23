import os
import sys
import zlib
import re
import argparse
import struct
import threading
import time
import requests
import urllib3
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

BANNER = r"""
   ____ _ _____        _       _               
  / ___(_) |__  |__  _ __   __ _| |_ ___| |__   ___ _ __ 
 | |  _| | __/ __| '_ \ / _` | __/ __| '_ \ / _ \ '__|
 | |_| | | |_\__ \ | | | (_| | || (__| | | |  __/ |   
  \____|_|\__|___/_| |_|\__,_|\__\___|_| |_|\___|_|   
                                                      
    .git Directory Reconstructor & Extractor
    Made by baba01hacker
"""

class GitSnatcher:
    def __init__(self, args):
        base_url = args.url
        if not base_url.endswith('/'):
            base_url += '/'
        if not base_url.endswith('.git/'):
            base_url += '.git/'
            
        self.base_url = base_url
        self.out_dir = args.output_dir
        self.threads = args.threads
        self.timeout = args.timeout
        self.delay = args.delay
        self.max_retries = getattr(args, 'retries', 3)
        self.verify_ssl = not args.insecure
        self.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        
        self.headers = {"User-Agent": args.user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if args.headers:
            for h in args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.headers[k.strip()] = v.strip()

        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)

        self.downloaded = set()
        self.queue = set()
        self.lock = threading.Lock()
        
        self.total_extracted = 0
        self.objects_found = 0
        
        self.initial_files = [
            'HEAD', 'config', 'description', 'info/exclude',
            'info/refs', 'logs/HEAD', 'logs/refs/heads/master',
            'logs/refs/heads/main', 'refs/heads/master', 'refs/heads/main',
            'refs/stash', 'index', 'packed-refs', 'objects/info/packs',
            'objects/info/alternates', 'shallow',
        ]

    def print_msg(self, level, msg):
        if level == "success":
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {msg}")
        elif level == "info":
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {msg}")
        elif level == "warning":
            print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")
        elif level == "error":
            print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")
        elif level == "status":
            sys.stdout.write(f"\r{Colors.OKCYAN}[>]{Colors.ENDC} {msg}")
            sys.stdout.flush()

    def download_file(self, path):
        with self.lock:
            if path in self.downloaded:
                return None
            self.downloaded.add(path)

        url = urljoin(self.base_url, path)
        out_path = os.path.join(self.out_dir, path)

        last_error = None
        for attempt in range(self.max_retries):
            if attempt > 0:
                backoff = min(2 ** attempt, 8)
                time.sleep(backoff)

            if self.delay > 0:
                time.sleep(self.delay)

            try:
                resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl,
                                        allow_redirects=False)
                if resp.status_code == 429:
                    retry_after = resp.headers.get('Retry-After', '5')
                    try:
                        time.sleep(float(retry_after))
                    except ValueError:
                        time.sleep(5)
                    continue

                if resp.status_code != 200:
                    last_error = f"HTTP {resp.status_code}"
                    continue

                data = resp.content
                # Filter out HTML responses (soft 404s, block pages, directory listings)
                if data and (b'<html' in data[:200].lower() or b'<!doctype' in data[:200].lower()):
                    return None

                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'wb') as f:
                    f.write(data)

                with self.lock:
                    self.total_extracted += 1
                    self.print_msg("status",
                        f"Extracted: {self.total_extracted} | Queue: {len(self.queue)} | {path[:50]}")

                return data

            except requests.exceptions.RequestException as e:
                last_error = str(e)[:80]
                continue

        return None

    def get_object_path(self, sha1):
        return f"objects/{sha1[:2]}/{sha1[2:]}"

    def parse_object(self, data, obj_type_hint=None):
        try:
            decompressed = zlib.decompress(data)
        except zlib.error:
            return []

        hashes = set()

        # Extract hashes from tree objects with proper binary parsing.
        # Git tree modes: 040000 (tree), 100644 (blob), 100755 (executable),
        # 120000 (symlink), 160000 (commit/submodule), 40000 (tree - old style).
        # Format per entry: "<mode> <name>\x00<20-byte sha1>"
        tree_pattern = re.compile(
            b'(?:100644|100755|040000|40000|120000|160000) [^\x00]+\x00(.{20})'
        )
        for match in tree_pattern.findall(decompressed):
            hashes.add(match.hex())

        # Fallback: scan for 40-char hex strings (useful for tag/commit objects).
        if not hashes:
            matches = re.findall(b'[0-9a-f]{40}', decompressed)
            for match in matches:
                hashes.add(match.decode('ascii'))

        return list(hashes)

    def extract_hashes_from_text(self, data):
        if not data:
            return []
        matches = re.findall(b'[0-9a-f]{40}', data)
        return [m.decode('ascii') for m in matches]

    def parse_index(self, data):
        hashes = set()
        if len(data) < 12:
            return []
        
        signature, version, entries = struct.unpack('>4sII', data[:12])
        if signature != b'DIRC':
            return []
            
        offset = 12
        for _ in range(entries):
            if offset + 62 > len(data):
                break
            sha1 = data[offset+40:offset+60]
            hashes.add(sha1.hex())
            
            flags = struct.unpack('>H', data[offset+60:offset+62])[0]
            is_extended = (flags & 0x4000) != 0 and version >= 3
            fixed_len = 64 if is_extended else 62
            
            if offset + fixed_len > len(data):
                break
                
            if version == 4:
                pos = offset + fixed_len
                while pos < len(data) and (data[pos] & 0x80):
                    pos += 1
                pos += 1
                nul_pos = data.find(b'\x00', pos)
                if nul_pos == -1: break
                offset = nul_pos + 1
            else:
                nul_pos = data.find(b'\x00', offset + fixed_len)
                if nul_pos == -1: break
                actual_name_length = nul_pos - (offset + fixed_len)
                entry_len = fixed_len + actual_name_length
                entry_len += 8 - (entry_len % 8)
                offset += entry_len
            
        return list(hashes)

    def parse_pack_index(self, data):
        """Parse a .idx file (v1 or v2) and return all object SHA1 hashes."""
        hashes = []
        if len(data) < 8:
            return hashes

        # v2 magic: \xff\x74\x4f\x63
        if data[:4] == b'\xfftOc':
            version = struct.unpack('>I', data[4:8])[0]
            if version != 2:
                return hashes

            # Fanout table: 256 × 4-byte big-endian counts
            fanout = struct.unpack('>256I', data[8:1032])
            obj_count = fanout[255]

            sha1_start = 1032
            sha1_end = sha1_start + obj_count * 20
            if sha1_end > len(data):
                return hashes

            for i in range(obj_count):
                offset = sha1_start + i * 20
                hashes.append(data[offset:offset + 20].hex())

        else:
            # v1 format: fanout table starts at offset 0 (no header)
            fanout = struct.unpack('>256I', data[0:1024])
            obj_count = fanout[255]

            sha1_start = 1024 + obj_count * 4  # skip 4-byte offsets (v1)
            sha1_end = sha1_start + obj_count * 20
            if sha1_end > len(data):
                return hashes

            for i in range(obj_count):
                offset = sha1_start + i * 20
                hashes.append(data[offset:offset + 20].hex())

        return hashes

    def parse_packed_refs(self, data):
        """Parse packed-refs content and return ref -> sha1 mappings."""
        refs = {}
        for line in data.split(b'\n'):
            line = line.strip()
            if not line or line.startswith(b'#') or line.startswith(b'^'):
                continue
            parts = line.split(b' ', 1)
            if len(parts) == 2 and len(parts[0]) == 40:
                sha1 = parts[0].decode('ascii')
                ref_name = parts[1].decode('ascii')
                refs[ref_name] = sha1
        return refs

    def run(self):
        print(Colors.OKCYAN + BANNER.replace("baba01hacker", f"{Colors.BOLD}baba01hacker{Colors.ENDC}{Colors.OKCYAN}") + Colors.ENDC)
        self.print_msg("info", f"Target: {Colors.BOLD}{self.base_url}{Colors.ENDC}")
        self.print_msg("info", f"Threads: {self.threads} | Timeout: {self.timeout}s | Retries: {self.max_retries}")
        os.makedirs(self.out_dir, exist_ok=True)

        print("-" * 50)
        self.print_msg("info", "Phase 1: Enumerating repository structure...")

        # Step 1: Download HEAD first to determine default branch
        head_data = self.download_file('HEAD')
        default_branch = None
        if head_data:
            head_text = head_data.decode('utf-8', errors='ignore').strip()
            if head_text.startswith('ref: '):
                default_branch = head_text[5:].strip()
                self.print_msg("info", f"HEAD → {default_branch}")

        # Build dynamic initial file list
        dynamic_files = list(self.initial_files)
        if default_branch:
            dynamic_files.extend([
                default_branch,
                f"logs/{default_branch}",
            ])

        # Try common alternative branches if no HEAD or detached
        for branch in ('refs/heads/master', 'refs/heads/main', 'refs/heads/develop',
                       'refs/heads/dev', 'refs/heads/staging'):
            if branch not in dynamic_files:
                dynamic_files.append(branch)

        for path in dynamic_files:
            if path in self.downloaded:
                continue
            data = self.download_file(path)
            if not data:
                continue

            if path == 'index':
                new_hashes = self.parse_index(data)
                self.queue.update(new_hashes)
                continue

            if path == 'packed-refs':
                refs = self.parse_packed_refs(data)
                for ref_name, sha1 in refs.items():
                    self.queue.add(sha1)
                    # Also download the ref file itself
                    self.download_file(ref_name)
                self.print_msg("info", f"packed-refs: {len(refs)} refs discovered")
                continue

            if path.endswith('.idx'):
                hashes = self.parse_pack_index(data)
                self.queue.update(hashes)
                # Also grab the corresponding .pack file
                pack_path = path.replace('.idx', '.pack')
                self.download_file(pack_path)
                self.print_msg("success", f"Pack index parsed: {len(hashes)} objects from {path}")
                continue

            if path == 'objects/info/packs':
                # Parse packs listing to find .idx files
                try:
                    text = data.decode('utf-8', errors='ignore')
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#') and line.endswith('.pack'):
                            idx_path = line.replace('.pack', '.idx')
                            pack_path = f"objects/pack/{idx_path}" if '/' not in line else line.replace('.pack', '.idx')
                            # Try both packed path and loose objects/pack path
                            idx_data = self.download_file(pack_path)
                            if idx_data:
                                hashes = self.parse_pack_index(idx_data)
                                self.queue.update(hashes)
                                self.download_file(pack_path.replace('.idx', '.pack'))
                                self.print_msg("success", f"Pack: {len(hashes)} objects from {pack_path}")
                except Exception:
                    pass
                continue

            if path == 'objects/info/alternates':
                try:
                    text = data.decode('utf-8', errors='ignore')
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.print_msg("warning", f"Alternate object DB: {line}")
                except Exception:
                    pass
                continue

            if path == 'shallow':
                hashes = self.extract_hashes_from_text(data)
                self.queue.update(hashes)
                self.print_msg("info", f"Shallow repo: {len(hashes)} boundary commits")
                continue

            # Generic text-based hash extraction for everything else
            new_hashes = self.extract_hashes_from_text(data)
            self.queue.update(new_hashes)

        print("\n" + "-" * 50)
        self.print_msg("info", f"Phase 2: Recursively fetching {len(self.queue)} discovered objects...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while self.queue:
                current_batch = list(self.queue)
                self.queue.clear()

                futures = {}
                for sha1 in current_batch:
                    obj_path = self.get_object_path(sha1)
                    with self.lock:
                        if obj_path not in self.downloaded:
                            futures[executor.submit(self.download_file, obj_path)] = sha1

                for future in as_completed(futures):
                    sha1 = futures[future]
                    data = future.result()
                    if data:
                        new_hashes = self.parse_object(data)
                        for h in new_hashes:
                            obj_path = self.get_object_path(h)
                            with self.lock:
                                if obj_path not in self.downloaded:
                                    self.queue.add(h)

        print("\n" + "-" * 50)
        self.print_msg("success", f"Extraction Complete. Reconstructed {self.total_extracted} files.")
        self.print_msg("success", f"Saved to directory: {self.out_dir}")
        self.print_msg("info", "Tip: Run 'git status' or 'git checkout .' inside the output directory.")

def main():
    parser = argparse.ArgumentParser(description="GitSnatcher - Professional .git Repository Extractor")
    parser.add_argument("-u", "--url", required=True, help="URL to the target .git directory")
    parser.add_argument("-o", "--output-dir", required=True, help="Directory to save the downloaded files")
    
    perf_group = parser.add_argument_group("Performance Options")
    perf_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    perf_group.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    perf_group.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    perf_group.add_argument("--retries", type=int, default=3, help="Max retries per failed request (default: 3)")
    
    net_group = parser.add_argument_group("Network & Evasion Options")
    net_group.add_argument("-x", "--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    net_group.add_argument("-k", "--insecure", action="store_true", help="Disable SSL/TLS certificate verification")
    net_group.add_argument("-A", "--user-agent", help="Custom User-Agent string")
    net_group.add_argument("-H", "--headers", nargs="*", help="Custom headers (e.g. 'Authorization: Bearer token')")

    args = parser.parse_args()
    
    try:
        snatcher = GitSnatcher(args)
        snatcher.run()
    except KeyboardInterrupt:
        print("\n")
        print(f"{Colors.WARNING}[!]{Colors.ENDC} Interrupted by user. Exiting safely.")
        sys.exit(0)

if __name__ == "__main__":
    main()
