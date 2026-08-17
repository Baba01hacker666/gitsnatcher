from .cli import main, __version__
from .extractor import GitSnatcher
from .parser import GitParser
from .dumper import GitDumper
from .scanner import SecretScanner
from .ui import Colors, BANNER, log_msg

__all__ = [
    'GitSnatcher',
    'GitParser',
    'GitDumper',
    'SecretScanner',
    'Colors',
    'BANNER',
    'main',
    '__version__',
]

if __name__ == '__main__':
    main()
