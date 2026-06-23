import unittest
import struct
import zlib
import argparse
from gitsnatcher.main import GitSnatcher


def _make_args(**overrides):
    defaults = dict(
        url="http://example.com/.git/",
        output_dir="/tmp/out",
        threads=1,
        timeout=10,
        delay=0,
        retries=1,
        insecure=True,
        proxy=None,
        user_agent=None,
        headers=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestGitSnatcher(unittest.TestCase):
    def test_extract_hashes_from_text(self):
        snatcher = GitSnatcher(_make_args())
        data = b"hello 9136fa5eeb000882e38c3bc67732d8fc95e2df40 world"
        hashes = snatcher.extract_hashes_from_text(data)
        self.assertIn("9136fa5eeb000882e38c3bc67732d8fc95e2df40", hashes)

    def test_extract_hashes_from_text_empty(self):
        snatcher = GitSnatcher(_make_args())
        self.assertEqual(snatcher.extract_hashes_from_text(None), [])
        self.assertEqual(snatcher.extract_hashes_from_text(b""), [])


class TestParseObject(unittest.TestCase):
    def test_tree_with_040000_mode(self):
        """Tree objects use mode 040000 for subtrees — this must be discovered."""
        snatcher = GitSnatcher(_make_args())

        # Build a synthetic git tree object with a subtree entry (040000)
        subtree_sha1 = b"\x11" * 20
        entry = b"040000 subdir\x00" + subtree_sha1

        # Git tree object header: "tree <size>\x00"
        tree_body = entry
        tree_obj = b"tree %d\x00" % len(tree_body) + tree_body
        compressed = zlib.compress(tree_obj)

        hashes = snatcher.parse_object(compressed)
        self.assertIn(subtree_sha1.hex(), hashes)

    def test_tree_with_mixed_entries(self):
        """Tree with blob, executable, subtree, and symlink."""
        snatcher = GitSnatcher(_make_args())

        blob_sha1 = b"\xaa" * 20
        exe_sha1 = b"\xbb" * 20
        tree_sha1 = b"\xcc" * 20
        symlink_sha1 = b"\xdd" * 20

        entries = (
            b"100644 file.txt\x00" + blob_sha1 +
            b"100755 script.sh\x00" + exe_sha1 +
            b"040000 lib\x00" + tree_sha1 +
            b"120000 link\x00" + symlink_sha1
        )

        tree_obj = b"tree %d\x00" % len(entries) + entries
        compressed = zlib.compress(tree_obj)

        hashes = snatcher.parse_object(compressed)
        self.assertIn(blob_sha1.hex(), hashes)
        self.assertIn(exe_sha1.hex(), hashes)
        self.assertIn(tree_sha1.hex(), hashes)
        self.assertIn(symlink_sha1.hex(), hashes)
        self.assertEqual(len(hashes), 4)

    def test_commit_object_fallback(self):
        """Commit objects don't match the tree regex, so fallback hex scan kicks in."""
        snatcher = GitSnatcher(_make_args())

        tree_sha1 = b"\x11" * 20
        parent_sha1 = b"\x22" * 20

        commit_body = (
            b"tree " + tree_sha1.hex().encode() + b"\n"
            b"parent " + parent_sha1.hex().encode() + b"\n"
            b"author test <test@x.com> 0 +0000\n"
            b"committer test <test@x.com> 0 +0000\n"
            b"\n"
            b"commit message\n"
        )

        commit_obj = b"commit %d\x00" % len(commit_body) + commit_body
        compressed = zlib.compress(commit_obj)

        hashes = snatcher.parse_object(compressed)
        self.assertIn(tree_sha1.hex(), hashes)
        self.assertIn(parent_sha1.hex(), hashes)

    def test_invalid_data(self):
        snatcher = GitSnatcher(_make_args())
        self.assertEqual(snatcher.parse_object(b"not zlib data"), [])


class TestParsePackIndex(unittest.TestCase):
    def test_v2_empty(self):
        snatcher = GitSnatcher(_make_args())
        hashes = snatcher.parse_pack_index(b"")
        self.assertEqual(hashes, [])

    def test_v2_single_object(self):
        snatcher = GitSnatcher(_make_args())

        sha1 = b"\xab" * 20
        obj_count = 1

        # Build v2 .idx header
        magic = b"\xfftOc"
        version = struct.pack(">I", 2)

        # fanout table: cumulative counts, so for 1 object they're all 1
        fanout = struct.pack(">256I", *([1] * 256))

        # sha1 list
        sha1_list = sha1 * obj_count

        # crc32 list (4 bytes per object)
        crc32_list = b"\x00" * (4 * obj_count)

        # offset list (4 bytes per object)
        offset_list = struct.pack(">I", 0)

        data = magic + version + fanout + sha1_list + crc32_list + offset_list

        hashes = snatcher.parse_pack_index(data)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0], sha1.hex())

    def test_v2_many_objects(self):
        snatcher = GitSnatcher(_make_args())

        obj_count = 100
        sha1s = [bytes([i % 256] * 20) for i in range(obj_count)]

        magic = b"\xfftOc"
        version = struct.pack(">I", 2)

        # Build proper fanout table
        fanout_values = []
        for first_byte in range(256):
            count = sum(1 for s in sha1s if s[0] <= first_byte)
            fanout_values.append(count)
        fanout = struct.pack(">256I", *fanout_values)

        sha1_list = b"".join(sha1s)
        crc32_list = b"\x00" * (4 * obj_count)
        offset_list = struct.pack(">" + "I" * obj_count, *range(obj_count))

        data = magic + version + fanout + sha1_list + crc32_list + offset_list

        hashes = snatcher.parse_pack_index(data)
        self.assertEqual(len(hashes), obj_count)

    def test_v2_wrong_version(self):
        snatcher = GitSnatcher(_make_args())
        data = b"\xfftOc" + struct.pack(">I", 999)  # unknown version
        hashes = snatcher.parse_pack_index(data)
        self.assertEqual(hashes, [])

    def test_v1_single_object(self):
        snatcher = GitSnatcher(_make_args())

        sha1 = b"\xcd" * 20
        obj_count = 1

        # v1: no magic/version, just fanout table
        fanout = struct.pack(">256I", *([1] * 256))
        offsets = struct.pack(">I", 0)  # v1 uses 4-byte offsets
        sha1_list = sha1 * obj_count

        data = fanout + offsets + sha1_list

        hashes = snatcher.parse_pack_index(data)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0], sha1.hex())


class TestParsePackedRefs(unittest.TestCase):
    def test_basic(self):
        snatcher = GitSnatcher(_make_args())
        data = (
            b"# pack-refs with: peeled fully-peeled sorted\n"
            b"abc123abc123abc123abc123abc123abc123abc1 refs/heads/main\n"
            b"^def456def456def456def456def456def456def4\n"
            b"fed987fed987fed987fed987fed987fed987fed9 refs/heads/develop\n"
            b"1111222233334444555566667777888899990000 refs/tags/v1.0\n"
        )

        refs = snatcher.parse_packed_refs(data)
        self.assertEqual(len(refs), 3)
        self.assertEqual(refs["refs/heads/main"], "abc123abc123abc123abc123abc123abc123abc1")
        self.assertEqual(refs["refs/heads/develop"], "fed987fed987fed987fed987fed987fed987fed9")
        self.assertEqual(refs["refs/tags/v1.0"], "1111222233334444555566667777888899990000")
        # Peeled line (^) should be skipped
        self.assertNotIn("^def456def456def456def456def456def456def4", refs)

    def test_empty(self):
        snatcher = GitSnatcher(_make_args())
        refs = snatcher.parse_packed_refs(b"")
        self.assertEqual(refs, {})

    def test_only_comments(self):
        snatcher = GitSnatcher(_make_args())
        refs = snatcher.parse_packed_refs(b"# comment only\n# another comment\n")
        self.assertEqual(refs, {})


class TestParseIndex(unittest.TestCase):
    def test_valid_index_v2(self):
        snatcher = GitSnatcher(_make_args())

        sha1 = b"\xef" * 20
        signature = b"DIRC"
        version = struct.pack(">I", 2)
        entry_count = struct.pack(">I", 1)

        # Entry: ctime, mtime, dev, ino, mode, uid, gid, size, sha1, flags
        entry = (
            struct.pack(">I", 0) * 4  # ctime_sec, ctime_nsec, mtime_sec, mtime_nsec
            + struct.pack(">I", 0) * 4  # dev, ino, mode, uid
            + struct.pack(">I", 0) * 2  # gid, size
            + sha1
            + struct.pack(">H", 7)  # flags: name length = 7
        )
        name = b"foo.txt\x00"
        # padding to 8-byte boundary: 62 + 7 + 1 = 70 → pad to 72
        padding = b"\x00" * (8 - ((62 + 7 + 1) % 8))

        index_data = signature + version + entry_count + entry + name + padding

        hashes = snatcher.parse_index(index_data)
        self.assertIn(sha1.hex(), hashes)

    def test_invalid_signature(self):
        snatcher = GitSnatcher(_make_args())
        data = b"XXXX" + b"\x00" * 100
        self.assertEqual(snatcher.parse_index(data), [])

    def test_truncated_data(self):
        snatcher = GitSnatcher(_make_args())
        self.assertEqual(snatcher.parse_index(b"\x00" * 4), [])


if __name__ == "__main__":
    unittest.main()
