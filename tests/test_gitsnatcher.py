import unittest
import argparse
from gitsnatcher.main import GitSnatcher

class TestGitSnatcher(unittest.TestCase):
    def test_extract_hashes_from_text(self):
        args = argparse.Namespace(
            url="http://example.com/.git/",
            output_dir="/tmp/out",
            threads=1,
            timeout=10,
            delay=0,
            insecure=True,
            proxy=None,
            user_agent=None,
            headers=None
        )
        snatcher = GitSnatcher(args)
        data = b"hello 9136fa5eeb000882e38c3bc67732d8fc95e2df40 world"
        hashes = snatcher.extract_hashes_from_text(data)
        self.assertIn("9136fa5eeb000882e38c3bc67732d8fc95e2df40", hashes)

if __name__ == '__main__':
    unittest.main()
