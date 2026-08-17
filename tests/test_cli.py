import unittest
from gitsnatcher.cli import build_parser


class TestCLI(unittest.TestCase):
    def test_parser_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["-u", "http://example.com/.git/", "-o", "/tmp/repo"])
        self.assertEqual(args.url, "http://example.com/.git/")
        self.assertEqual(args.output_dir, "/tmp/repo")
        self.assertEqual(args.threads, 10)
        self.assertEqual(args.timeout, 10)
        self.assertEqual(args.delay, 0.0)
        self.assertEqual(args.retries, 3)
        self.assertFalse(args.insecure)
        self.assertFalse(args.restore)
        self.assertFalse(args.scan_secrets)

    def test_parser_custom_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "-u", "https://target.com",
            "-o", "./out",
            "-t", "25",
            "--delay", "0.5",
            "--timeout", "15",
            "--retries", "5",
            "-x", "http://127.0.0.1:8080",
            "-k",
            "--random-agent",
            "-H", "X-Custom: 123", "Authorization: Bearer test",
            "-c", "session=abc",
            "--auth", "admin:password",
            "-r",
            "-s",
            "--dump-history",
            "-q"
        ])
        self.assertEqual(args.url, "https://target.com")
        self.assertEqual(args.threads, 25)
        self.assertEqual(args.delay, 0.5)
        self.assertEqual(args.timeout, 15)
        self.assertEqual(args.retries, 5)
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")
        self.assertTrue(args.insecure)
        self.assertTrue(args.random_agent)
        self.assertEqual(args.headers, ["X-Custom: 123", "Authorization: Bearer test"])
        self.assertEqual(args.cookie, "session=abc")
        self.assertEqual(args.auth, "admin:password")
        self.assertTrue(args.restore)
        self.assertTrue(args.scan_secrets)
        self.assertTrue(args.dump_history)
        self.assertTrue(args.quiet)


if __name__ == "__main__":
    unittest.main()
