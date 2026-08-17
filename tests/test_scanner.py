import os
import shutil
import tempfile
import unittest
import zlib
from gitsnatcher.scanner import SecretScanner


class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.git_dir = os.path.join(self.test_dir, '.git')
        os.makedirs(os.path.join(self.git_dir, 'objects'), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_git_blob(self, content: str, sha1: str):
        raw = f"blob {len(content)}\x00{content}".encode('utf-8')
        compressed = zlib.compress(raw)
        obj_path = os.path.join(self.git_dir, 'objects', sha1[:2], sha1[2:])
        os.makedirs(os.path.dirname(obj_path), exist_ok=True)
        with open(obj_path, 'wb') as f:
            f.write(compressed)

    def test_detect_aws_and_github_keys(self):
        content = """
        AWS_KEY = "AKIA1234567890ABCDEF"
        GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        """
        sha = "1" * 40
        self._write_git_blob(content, sha)

        scanner = SecretScanner(self.git_dir)
        findings = scanner.scan_all_objects()

        rules_found = [f.rule for f in findings]
        self.assertIn("AWS Access Key", rules_found)
        self.assertIn("GitHub Token", rules_found)

    def test_detect_openai_and_private_keys(self):
        content = """
        sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Y...
        -----END RSA PRIVATE KEY-----
        """
        sha = "2" * 40
        self._write_git_blob(content, sha)

        scanner = SecretScanner(self.git_dir)
        findings = scanner.scan_all_objects()

        rules_found = [f.rule for f in findings]
        self.assertIn("OpenAI API Key", rules_found)
        self.assertIn("RSA/SSH Private Key", rules_found)

    def test_detect_database_uri(self):
        content = 'DATABASE_URL="postgres://admin:supersecretpassword@db.example.com:5432/production"'
        sha = "3" * 40
        self._write_git_blob(content, sha)

        scanner = SecretScanner(self.git_dir)
        findings = scanner.scan_all_objects()

        rules_found = [f.rule for f in findings]
        self.assertIn("Database Connection URI", rules_found)

    def test_detect_sensitive_env_file(self):
        env_path = os.path.join(self.test_dir, ".env")
        with open(env_path, "w") as f:
            f.write("SECRET_KEY=123456\n")

        scanner = SecretScanner(self.git_dir)
        findings = scanner.scan_all_objects()

        categories = [f.category for f in findings]
        self.assertIn("Sensitive File", categories)


if __name__ == "__main__":
    unittest.main()
