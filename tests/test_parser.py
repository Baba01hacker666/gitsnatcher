import unittest
import struct
import zlib
from gitsnatcher.parser import GitParser, CommitInfo, TagInfo, TreeEntry


class TestGitParserObject(unittest.TestCase):
    def test_decompress_valid_blob(self):
        content = b"console.log('hello world');\n"
        raw_obj = b"blob %d\x00%s" % (len(content), content)
        compressed = zlib.compress(raw_obj)

        res = GitParser.decompress_object(compressed)
        self.assertIsNotNone(res)
        obj_type, size, data = res
        self.assertEqual(obj_type, "blob")
        self.assertEqual(size, len(content))
        self.assertEqual(data, content)

    def test_decompress_invalid_data(self):
        self.assertIsNone(GitParser.decompress_object(b"not zlib"))
        self.assertIsNone(GitParser.decompress_object(b""))
        self.assertIsNone(GitParser.decompress_object(None))

    def test_decompress_invalid_header(self):
        compressed = zlib.compress(b"invalid_header_without_null")
        self.assertIsNone(GitParser.decompress_object(compressed))


class TestGitParserTree(unittest.TestCase):
    def test_parse_tree_entries(self):
        blob_sha = b"\x12" * 20
        exec_sha = b"\x34" * 20
        tree_sha = b"\x56" * 20

        payload = (
            b"100644 app.py\x00" + blob_sha +
            b"100755 run.sh\x00" + exec_sha +
            b"040000 src\x00" + tree_sha
        )

        entries = GitParser.parse_tree(payload)
        self.assertEqual(len(entries), 3)

        self.assertEqual(entries[0].mode, "100644")
        self.assertEqual(entries[0].name, "app.py")
        self.assertEqual(entries[0].sha1, blob_sha.hex())
        self.assertFalse(entries[0].is_dir)

        self.assertEqual(entries[1].mode, "100755")
        self.assertEqual(entries[1].name, "run.sh")
        self.assertEqual(entries[1].sha1, exec_sha.hex())
        self.assertFalse(entries[1].is_dir)

        self.assertEqual(entries[2].mode, "040000")
        self.assertEqual(entries[2].name, "src")
        self.assertEqual(entries[2].sha1, tree_sha.hex())
        self.assertTrue(entries[2].is_dir)


class TestGitParserCommit(unittest.TestCase):
    def test_parse_commit_single_parent(self):
        tree_hex = "a" * 40
        parent_hex = "b" * 40
        commit_payload = (
            f"tree {tree_hex}\n"
            f"parent {parent_hex}\n"
            "author Alice <alice@example.com> 1600000000 +0000\n"
            "committer Bob <bob@example.com> 1600000000 +0000\n"
            "\n"
            "Initial commit message"
        ).encode('utf-8')

        info = GitParser.parse_commit(commit_payload)
        self.assertEqual(info.tree, tree_hex)
        self.assertEqual(info.parents, [parent_hex])
        self.assertIn("Alice", info.author)
        self.assertIn("Bob", info.committer)
        self.assertEqual(info.message, "Initial commit message")

    def test_parse_commit_merge(self):
        tree_hex = "1" * 40
        p1 = "2" * 40
        p2 = "3" * 40
        commit_payload = (
            f"tree {tree_hex}\n"
            f"parent {p1}\n"
            f"parent {p2}\n"
            "author Dev <dev@x.com> 0 +0000\n"
            "\n"
            "Merge branch 'feat'"
        ).encode('utf-8')

        info = GitParser.parse_commit(commit_payload)
        self.assertEqual(info.tree, tree_hex)
        self.assertEqual(info.parents, [p1, p2])
        self.assertEqual(info.message, "Merge branch 'feat'")


class TestGitParserTag(unittest.TestCase):
    def test_parse_annotated_tag(self):
        target_sha = "c" * 40
        tag_payload = (
            f"object {target_sha}\n"
            "type commit\n"
            "tag v1.0.0\n"
            "tagger Release <rel@x.com> 1600000000 +0000\n"
            "\n"
            "Release version 1.0.0"
        ).encode('utf-8')

        tag_info = GitParser.parse_tag(tag_payload)
        self.assertEqual(tag_info.target_object, target_sha)
        self.assertEqual(tag_info.target_type, "commit")
        self.assertEqual(tag_info.tag_name, "v1.0.0")
        self.assertIn("Release", tag_info.tagger)
        self.assertEqual(tag_info.message, "Release version 1.0.0")


class TestGitParserIndexExtensions(unittest.TestCase):
    def test_parse_index_with_tree_extension(self):
        entry_sha = b"\x11" * 20
        tree_sha1 = b"\x22" * 20
        tree_sha2 = b"\x33" * 20

        # Build index header
        signature = b"DIRC"
        version = struct.pack(">I", 2)
        entry_count = struct.pack(">I", 1)

        entry = (
            struct.pack(">I", 0) * 8 +
            struct.pack(">I", 0) * 2 +
            entry_sha +
            struct.pack(">H", 7)
        )
        name = b"foo.txt\x00"
        padding = b"\x00" * (8 - ((62 + 7 + 1) % 8))

        # Build TREE extension
        tree_ext_data = (
            b"\x00" + b"1 0\n" + tree_sha1 +
            b"subdir\x00" + b"1 0\n" + tree_sha2
        )
        ext_sig = b"TREE"
        ext_len = struct.pack(">I", len(tree_ext_data))
        checksum = b"\x00" * 20

        index_data = signature + version + entry_count + entry + name + padding + ext_sig + ext_len + tree_ext_data + checksum

        hashes = GitParser.parse_index(index_data)
        self.assertIn(entry_sha.hex(), hashes)
        self.assertIn(tree_sha1.hex(), hashes)
        self.assertIn(tree_sha2.hex(), hashes)


class TestGitParserReflogAndConfig(unittest.TestCase):
    def test_parse_reflog(self):
        sha1 = "a" * 40
        sha2 = "b" * 40
        data = f"{sha1} {sha2} Author <a@b.com> 1600000000 +0000\tcommit: update readme\n".encode('utf-8')
        records = GitParser.parse_reflog(data)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0][0], sha1)
        self.assertEqual(records[0][1], sha2)
        self.assertEqual(records[0][2], "commit: update readme")

    def test_parse_git_config(self):
        config_text = b"""[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
    objectformat = sha1
[remote "origin"]
    url = https://github.com/org/repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
[branch "feature/login"]
    remote = origin
    merge = refs/heads/feature/login
[submodule "vendor/lib"]
    url = https://github.com/vendor/lib.git
"""
        res = GitParser.parse_git_config(config_text)
        self.assertEqual(res["remotes"].get("origin"), "https://github.com/org/repo.git")
        self.assertIn("main", res["branches"])
        self.assertIn("feature/login", res["branches"])
        self.assertEqual(res["submodules"].get("vendor/lib"), "https://github.com/vendor/lib.git")
        self.assertEqual(res["object_format"], "sha1")


if __name__ == "__main__":
    unittest.main()
