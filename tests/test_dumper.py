import os
import shutil
import tempfile
import unittest
import zlib
import struct
from gitsnatcher.dumper import GitDumper


class TestGitDumper(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.git_dir = os.path.join(self.test_dir, '.git')
        self.worktree_dir = os.path.join(self.test_dir, 'worktree')
        os.makedirs(os.path.join(self.git_dir, 'objects'), exist_ok=True)
        os.makedirs(self.worktree_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_git_object(self, obj_type: str, content: bytes, sha1: str):
        payload = f"{obj_type} {len(content)}\x00".encode('ascii') + content
        compressed = zlib.compress(payload)
        obj_path = os.path.join(self.git_dir, 'objects', sha1[:2], sha1[2:])
        os.makedirs(os.path.dirname(obj_path), exist_ok=True)
        with open(obj_path, 'wb') as f:
            f.write(compressed)

    def test_restore_from_index(self):
        blob_content = b"print('hello world')\n"
        blob_sha_bytes = b"\xaa" * 20
        blob_sha = blob_sha_bytes.hex()
        self._write_git_object("blob", blob_content, blob_sha)

        # Build synthetic index
        signature = b"DIRC"
        version = struct.pack(">I", 2)
        entry_count = struct.pack(">I", 1)
        entry = (
            struct.pack(">I", 0) * 6 +
            struct.pack(">I", 0o100644) +  # mode
            struct.pack(">I", 0) * 3 +
            blob_sha_bytes +
            struct.pack(">H", 8)  # flags: len=8
        )
        name = b"main.py\x00"
        padding = b"\x00" * (8 - ((62 + 8) % 8))
        index_data = signature + version + entry_count + entry + name + padding

        with open(os.path.join(self.git_dir, 'index'), 'wb') as f:
            f.write(index_data)

        dumper = GitDumper(self.git_dir, self.worktree_dir)
        restored = dumper.restore_from_index()
        self.assertEqual(restored, 1)

        restored_file = os.path.join(self.worktree_dir, "main.py")
        self.assertTrue(os.path.isfile(restored_file))
        with open(restored_file, 'rb') as f:
            self.assertEqual(f.read(), blob_content)

    def test_restore_tree_recursive(self):
        blob_content = b"#!/bin/bash\necho 'running'\n"
        blob_sha_bytes = b"\xbb" * 20
        blob_sha = blob_sha_bytes.hex()
        self._write_git_object("blob", blob_content, blob_sha)

        tree_payload = b"100755 script.sh\x00" + blob_sha_bytes
        tree_sha_bytes = b"\xcc" * 20
        tree_sha = tree_sha_bytes.hex()
        self._write_git_object("tree", tree_payload, tree_sha)

        dumper = GitDumper(self.git_dir, self.worktree_dir)
        restored = dumper.restore_tree_recursive(tree_sha, self.worktree_dir)
        self.assertEqual(restored, 1)

        script_path = os.path.join(self.worktree_dir, "script.sh")
        self.assertTrue(os.path.isfile(script_path))
        with open(script_path, 'rb') as f:
            self.assertEqual(f.read(), blob_content)


if __name__ == "__main__":
    unittest.main()
