import sys
import argparse
from .extractor import GitSnatcher
from .ui import Colors, BANNER

__version__ = "2.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gitsnatcher",
        description="GitSnatcher - Professional .git Repository Reconstructor & Intelligence Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  gitsnatcher -u http://target.com/.git/ -o ./loot
  gitsnatcher -u http://target.com/.git/ -o ./loot -t 20 -r -s
  gitsnatcher -u https://target.com/.git/ -o ./loot -x http://127.0.0.1:8080 -k --random-agent
  gitsnatcher -u http://target.com/.git/ -o ./loot -H "Authorization: Bearer token" -c "session=xyz"
"""
    )

    req_group = parser.add_argument_group("Required Arguments")
    req_group.add_argument("-u", "--url", required=True, help="URL to the target .git directory (e.g. http://target.com/.git/)")
    req_group.add_argument("-o", "--output-dir", required=True, help="Local directory to save the recovered repository")

    perf_group = parser.add_argument_group("Performance & Timing")
    perf_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    perf_group.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    perf_group.add_argument("--timeout", type=int, default=10, help="HTTP connection timeout in seconds (default: 10)")
    perf_group.add_argument("--retries", type=int, default=3, help="Max retries per request on network error (default: 3)")

    net_group = parser.add_argument_group("Network, Evasion & Auth")
    net_group.add_argument("-x", "--proxy", help="HTTP/HTTPS/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    net_group.add_argument("-k", "--insecure", action="store_true", help="Disable SSL/TLS certificate verification")
    net_group.add_argument("-A", "--user-agent", help="Custom User-Agent string")
    net_group.add_argument("--random-agent", action="store_true", help="Use randomized browser User-Agents")
    net_group.add_argument("-H", "--headers", nargs="*", help="Custom headers (e.g. 'Authorization: Bearer token')")
    net_group.add_argument("-c", "--cookie", help="Custom HTTP Cookie string (e.g. 'session=xyz; admin=1')")
    net_group.add_argument("--auth", help="HTTP Basic Auth (user:password) or Bearer Token")

    analysis_group = parser.add_argument_group("Post-Extraction & Intelligence")
    analysis_group.add_argument("-r", "--restore", action="store_true", help="Automatically checkout and restore working tree source files")
    analysis_group.add_argument("-s", "--scan-secrets", action="store_true", help="Scan recovered objects & configs for leaked API keys and secrets")
    analysis_group.add_argument("--dump-history", action="store_true", help="Display commit log history of recovered repository")

    output_group = parser.add_argument_group("Output & Formatting")
    output_group.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (suppress banners and progress animations)")
    output_group.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        snatcher = GitSnatcher(args)
        snatcher.run()
    except KeyboardInterrupt:
        print("\n")
        print(f"{Colors.WARNING}[!]{Colors.ENDC} Interrupted by user. Exiting safely.")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.FAIL}[-] Fatal Error: {e}{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
