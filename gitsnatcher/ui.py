import os
import sys

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

    @classmethod
    def disable(cls):
        cls.HEADER = ''
        cls.OKBLUE = ''
        cls.OKCYAN = ''
        cls.OKGREEN = ''
        cls.WARNING = ''
        cls.FAIL = ''
        cls.ENDC = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.UNDERLINE = ''

# Automatically disable colors if NO_COLOR is set or stdout is not a TTY
if os.environ.get('NO_COLOR') or not sys.stdout.isatty():
    if not os.environ.get('FORCE_COLOR'):
        Colors.disable()

BANNER = r"""
   ____ _ _____        _       _               
  / ___(_) |__  |__  _ __   __ _| |_ ___| |__   ___ _ __ 
 | |  _| | __/ __| '_ \ / _` | __/ __| '_ \ / _ \ '__|
 | |_| | | |_\__ \ | | | (_| | || (__| | | |  __/ |   
  \____|_|\__|___/_| |_|\__,_|\__\___|_| |_|\___|_|   
                                                      
    .git Directory Reconstructor & Intelligence Extractor
    Version 2.0.0 | Author: baba01hacker
"""

def print_banner(quiet=False):
    if quiet:
        return
    print(f"{Colors.OKCYAN}{BANNER}{Colors.ENDC}")

def log_msg(level, msg, quiet=False):
    if quiet and level not in ("error", "fatal"):
        return
    
    if level == "success":
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {msg}")
    elif level == "info":
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {msg}")
    elif level == "warning":
        print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")
    elif level == "error" or level == "fatal":
        print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}", file=sys.stderr)
    elif level == "secret":
        print(f"{Colors.FAIL}[SECRET]{Colors.ENDC} {msg}")
    elif level == "status":
        if sys.stdout.isatty():
            sys.stdout.write(f"\r\033[K{Colors.OKCYAN}[>]{Colors.ENDC} {msg}")
            sys.stdout.flush()
        else:
            # Piped/non-interactive: avoid flushing constantly
            pass

def format_size(num_bytes):
    """Format bytes into human readable string (KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"
