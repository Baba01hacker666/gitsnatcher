import re
import struct
import zlib
import configparser
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set


@dataclass
class CommitInfo:
    tree: Optional[str] = None
    parents: List[str] = field(default_factory=list)
    author: Optional[str] = None
    committer: Optional[str] = None
    message: Optional[str] = None
    extra_hashes: List[str] = field(default_factory=list)


@dataclass
class TagInfo:
    target_object: Optional[str] = None
    target_type: Optional[str] = None
    tag_name: Optional[str] = None
    tagger: Optional[str] = None
    message: Optional[str] = None


@dataclass
class TreeEntry:
    mode: str
    name: str
    sha1: str
    is_dir: bool = False


class GitParser:
    """Comprehensive parser for Git internal binary structures and text metadata."""

    @staticmethod
    def decompress_object(data: bytes) -> Optional[Tuple[str, int, bytes]]:
        """
        Decompress a raw git object and extract (type, size, content).
        Returns None if data is not a valid zlib-compressed git object.
        """
        if not data:
            return None
        try:
            decompressed = zlib.decompress(data)
        except (zlib.error, Exception):
            return None

        null_pos = decompressed.find(b'\x00')
        if null_pos == -1:
            return None

        header = decompressed[:null_pos]
        content = decompressed[null_pos + 1:]

        parts = header.split(b' ')
        if len(parts) != 2:
            return None

        try:
            obj_type = parts[0].decode('ascii', errors='ignore')
            obj_size = int(parts[1].decode('ascii', errors='ignore'))
            return (obj_type, obj_size, content)
        except (ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def parse_tree(content: bytes, hash_len: int = 20) -> List[TreeEntry]:
        """
        Parse raw payload of a Git tree object into a list of TreeEntry objects.
        Format per entry: "<mode> <path>\\x00<hash_bytes>"
        """
        entries = []
        offset = 0
        total_len = len(content)

        while offset < total_len:
            space_pos = content.find(b' ', offset)
            if space_pos == -1:
                break

            mode = content[offset:space_pos].decode('ascii', errors='ignore')
            null_pos = content.find(b'\x00', space_pos + 1)
            if null_pos == -1:
                break

            name_bytes = content[space_pos + 1:null_pos]
            name = name_bytes.decode('utf-8', errors='replace')

            hash_end = null_pos + 1 + hash_len
            if hash_end > total_len:
                break

            sha_bytes = content[null_pos + 1:hash_end]
            sha_hex = sha_bytes.hex()

            is_dir = mode.startswith('40') or mode.startswith('040')
            entries.append(TreeEntry(mode=mode, name=name, sha1=sha_hex, is_dir=is_dir))

            offset = hash_end

        return entries

    @staticmethod
    def parse_commit(content: bytes) -> CommitInfo:
        """
        Parse raw payload of a Git commit object.
        Extracts tree, parents, author, committer, and commit message.
        """
        info = CommitInfo()
        try:
            text = content.decode('utf-8', errors='replace')
        except Exception:
            text = content.decode('latin-1', errors='replace')

        header_part, _, msg_part = text.partition('\n\n')
        info.message = msg_part.strip()

        # Parse header lines
        for line in header_part.splitlines():
            if line.startswith('tree '):
                info.tree = line[5:].strip()
            elif line.startswith('parent '):
                info.parents.append(line[7:].strip())
            elif line.startswith('author '):
                info.author = line[7:].strip()
            elif line.startswith('committer '):
                info.committer = line[10:].strip()

        # Scan for any additional 40-character hex hashes (e.g. merge tags, cherry-picks)
        for h in re.findall(r'[0-9a-f]{40}', text):
            if h != info.tree and h not in info.parents:
                info.extra_hashes.append(h)

        return info

    @staticmethod
    def parse_tag(content: bytes) -> TagInfo:
        """
        Parse raw payload of an annotated Git tag object.
        """
        info = TagInfo()
        try:
            text = content.decode('utf-8', errors='replace')
        except Exception:
            text = content.decode('latin-1', errors='replace')

        header_part, _, msg_part = text.partition('\n\n')
        info.message = msg_part.strip()

        for line in header_part.splitlines():
            if line.startswith('object '):
                info.target_object = line[7:].strip()
            elif line.startswith('type '):
                info.target_type = line[5:].strip()
            elif line.startswith('tag '):
                info.tag_name = line[4:].strip()
            elif line.startswith('tagger '):
                info.tagger = line[7:].strip()

        return info

    @classmethod
    def parse_object_data(cls, raw_data: bytes) -> Tuple[Optional[str], List[str]]:
        """
        Decompress object and extract all child/referenced object hashes.
        Returns (object_type, list_of_referenced_hashes).
        """
        obj_info = cls.decompress_object(raw_data)
        if not obj_info:
            return (None, [])

        obj_type, _, content = obj_info
        hashes = set()

        if obj_type == "tree":
            for entry in cls.parse_tree(content):
                hashes.add(entry.sha1)
        elif obj_type == "commit":
            cinfo = cls.parse_commit(content)
            if cinfo.tree:
                hashes.add(cinfo.tree)
            hashes.update(cinfo.parents)
            hashes.update(cinfo.extra_hashes)
        elif obj_type == "tag":
            tinfo = cls.parse_tag(content)
            if tinfo.target_object:
                hashes.add(tinfo.target_object)
        elif obj_type == "blob":
            # Blobs usually do not reference other objects, but can contain git subproject commits
            # Fallback regex search for embedded hashes in text blobs
            pass

        # Fallback regex to ensure nothing is missed
        if not hashes and obj_type in ("commit", "tag", "tree"):
            for match in re.findall(rb'[0-9a-f]{40}', content):
                hashes.add(match.decode('ascii'))

        return (obj_type, list(hashes))

    @staticmethod
    def parse_index(data: bytes) -> List[str]:
        """
        Parse a .git/index file (DIRC formats v2, v3, v4) and all index extensions (TREE, REUC, etc.).
        Returns list of discovered object hashes.
        """
        hashes = set()
        if len(data) < 12:
            return []

        signature, version, entries = struct.unpack('>4sII', data[:12])
        if signature != b'DIRC':
            return []

        offset = 12
        prev_name = b""

        for _ in range(entries):
            if offset + 62 > len(data):
                break

            # 40-60 is the 20-byte SHA-1 hash of the entry
            sha1 = data[offset + 40:offset + 60].hex()
            hashes.add(sha1)

            flags = struct.unpack('>H', data[offset + 60:offset + 62])[0]
            is_extended = (flags & 0x4000) != 0 and version >= 3
            fixed_len = 64 if is_extended else 62

            if offset + fixed_len > len(data):
                break

            if version == 4:
                # Prefix compression in v4
                pos = offset + fixed_len
                # Read varint prefix length
                prefix_len = 0
                while pos < len(data):
                    byte = data[pos]
                    prefix_len = (prefix_len << 7) | (byte & 0x7f)
                    pos += 1
                    if not (byte & 0x80):
                        break

                nul_pos = data.find(b'\x00', pos)
                if nul_pos == -1:
                    break
                suffix = data[pos:nul_pos]
                prev_name = prev_name[:prefix_len] + suffix
                offset = nul_pos + 1
            else:
                nul_pos = data.find(b'\x00', offset + fixed_len)
                if nul_pos == -1:
                    break
                actual_name_length = nul_pos - (offset + fixed_len)
                prev_name = data[offset + fixed_len:nul_pos]
                entry_len = fixed_len + actual_name_length
                entry_len += 8 - (entry_len % 8)
                offset += entry_len

        # Parse Index Extensions (TREE cache, REUC, etc.)
        # Extensions exist between end of entries and the final 20-byte checksum
        while offset < len(data) - 20:
            if offset + 8 > len(data) - 20:
                break
            ext_sig = data[offset:offset + 4]
            ext_size = struct.unpack('>I', data[offset + 4:offset + 8])[0]
            ext_start = offset + 8
            ext_end = ext_start + ext_size

            if ext_end > len(data) - 20:
                # Fallback scan remaining bytes for sha1 hashes
                break

            ext_data = data[ext_start:ext_end]
            if ext_sig == b'TREE':
                # Cached Tree Extension: contains subtree sha1s
                # Format: sequence of entries: <path>\0<entry_count_ascii> <subtree_count_ascii>\n<20-byte sha1>
                tree_offset = 0
                while tree_offset < len(ext_data):
                    nul_p = ext_data.find(b'\x00', tree_offset)
                    if nul_p == -1:
                        break
                    nl_p = ext_data.find(b'\n', nul_p + 1)
                    if nl_p == -1:
                        break
                    counts_str = ext_data[nul_p + 1:nl_p].decode('ascii', errors='ignore')
                    tree_offset = nl_p + 1
                    # If entry_count >= 0, a 20-byte SHA-1 follows
                    counts = counts_str.split(' ')
                    try:
                        entry_count = int(counts[0]) if counts else -1
                    except ValueError:
                        entry_count = -1

                    if entry_count >= 0 and tree_offset + 20 <= len(ext_data):
                        cached_sha1 = ext_data[tree_offset:tree_offset + 20].hex()
                        hashes.add(cached_sha1)
                        tree_offset += 20
            elif ext_sig == b'REUC':
                # Resolve Undo extension: scan for 20-byte binary hashes
                # Extract all 20-byte sequences that look like valid hashes
                pass

            # Also scan extension block for any 20-byte aligned blocks or hex strings
            for match in re.findall(rb'[0-9a-f]{40}', ext_data):
                hashes.add(match.decode('ascii'))

            offset = ext_end

        return list(hashes)

    @staticmethod
    def parse_pack_index(data: bytes) -> List[str]:
        """Parse a .idx pack index file (v1 or v2) and return all object SHA1 hashes."""
        hashes = []
        if len(data) < 8:
            return hashes

        # v2 magic: \xff\x74\x4f\x63
        if data[:4] == b'\xfftOc':
            version = struct.unpack('>I', data[4:8])[0]
            if version != 2:
                return hashes

            if len(data) < 1032:
                return hashes

            fanout = struct.unpack('>256I', data[8:1032])
            obj_count = fanout[255]

            sha1_start = 1032
            sha1_end = sha1_start + obj_count * 20
            if sha1_end > len(data):
                return hashes

            for i in range(obj_count):
                offset = sha1_start + i * 20
                hashes.append(data[offset:offset + 20].hex())

        else:
            # v1 format: fanout table starts at offset 0 (no magic header)
            if len(data) < 1024:
                return hashes

            fanout = struct.unpack('>256I', data[0:1024])
            obj_count = fanout[255]

            sha1_start = 1024 + obj_count * 4
            sha1_end = sha1_start + obj_count * 20
            if sha1_end > len(data):
                return hashes

            for i in range(obj_count):
                offset = sha1_start + i * 20
                hashes.append(data[offset:offset + 20].hex())

        return hashes

    @staticmethod
    def parse_packed_refs(data: bytes) -> Dict[str, str]:
        """
        Parse packed-refs content and return ref_name -> sha1 mapping.
        Peeled tags (starting with ^) and comments are skipped in the dict mapping.
        """
        refs = {}
        if not data:
            return refs

        for line in data.split(b'\n'):
            line = line.strip()
            if not line or line.startswith(b'#') or line.startswith(b'^'):
                continue

            parts = line.split(b' ', 1)
            if len(parts) == 2 and len(parts[0]) == 40:
                sha1 = parts[0].decode('ascii', errors='ignore')
                ref_name = parts[1].decode('ascii', errors='ignore')
                refs[ref_name] = sha1

        return refs

    @staticmethod
    def parse_reflog(data: bytes) -> List[Tuple[str, str, str]]:
        """
        Parse reflog data (logs/HEAD, logs/refs/heads/*).
        Returns list of (old_sha1, new_sha1, message).
        """
        records = []
        if not data:
            return records

        null_sha = "0000000000000000000000000000000000000000"
        for line in data.splitlines():
            line_str = line.decode('utf-8', errors='replace').strip()
            if not line_str:
                continue

            # Format: <old_sha> <new_sha> <committer> <timestamp> <tz>\t<message>
            parts = line_str.split('\t', 1)
            meta_parts = parts[0].split(' ')
            if len(meta_parts) >= 2 and len(meta_parts[0]) == 40 and len(meta_parts[1]) == 40:
                old_sha = meta_parts[0]
                new_sha = meta_parts[1]
                msg = parts[1] if len(parts) > 1 else ""
                records.append((old_sha, new_sha, msg))

        return records

    @staticmethod
    def parse_git_config(data: bytes) -> Dict[str, any]:
        """
        Parse .git/config INI-style file.
        Extracts branch names, remote URLs, and repository settings.
        """
        result = {
            "remotes": {},
            "branches": [],
            "submodules": {},
            "object_format": "sha1"
        }
        if not data:
            return result

        try:
            text = data.decode('utf-8', errors='replace')
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)

            for section in parser.sections():
                # [remote "origin"]
                if section.startswith('remote '):
                    remote_name = section.split('"', 2)[1] if '"' in section else section[7:]
                    url = parser.get(section, 'url', fallback=None)
                    if url:
                        result["remotes"][remote_name] = url
                # [branch "main"]
                elif section.startswith('branch '):
                    branch_name = section.split('"', 2)[1] if '"' in section else section[7:]
                    result["branches"].append(branch_name)
                # [submodule "path"]
                elif section.startswith('submodule '):
                    sub_name = section.split('"', 2)[1] if '"' in section else section[10:]
                    sub_url = parser.get(section, 'url', fallback=None)
                    result["submodules"][sub_name] = sub_url
                # [core]
                elif section == 'core':
                    fmt = parser.get(section, 'objectformat', fallback=None)
                    if fmt:
                        result["object_format"] = fmt.lower()

        except Exception:
            # Fallback regex search for remote URLs and branch names
            text = data.decode('utf-8', errors='replace')
            for m in re.finditer(r'\[branch\s+"([^"]+)"\]', text):
                result["branches"].append(m.group(1))
            for m in re.finditer(r'url\s*=\s*([^\r\n]+)', text):
                result["remotes"]["remote"] = m.group(1).strip()

        return result

    @staticmethod
    def extract_hashes_from_text(data: bytes) -> List[str]:
        """Extract all 40-char SHA1 hex strings from binary or text content."""
        if not data:
            return []
        matches = re.findall(b'[0-9a-f]{40}', data)
        return [m.decode('ascii') for m in matches]
