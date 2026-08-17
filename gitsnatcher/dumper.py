import os
import struct
import subprocess
import zlib
from typing import Optional, Dict, List, Tuple
from .parser import GitParser, TreeEntry
from .ui import log_msg


class GitDumper:
    """Restores source code and working tree from reconstructed .git directories."""

    def __init__(self, git_dir: str, worktree_dir: Optional[str] = None):
        """
        git_dir: path to the recovered .git directory (or directory containing .git)
        worktree_dir: path where working files will be checked out
        """
        if os.path.basename(os.path.normpath(git_dir)) == '.git':
            self.git_dir = os.path.abspath(git_dir)
            self.worktree_dir = os.path.abspath(worktree_dir or os.path.dirname(self.git_dir))
        else:
            self.git_dir = os.path.abspath(os.path.join(git_dir, '.git')) if os.path.exists(os.path.join(git_dir, '.git')) else os.path.abspath(git_dir)
            self.worktree_dir = os.path.abspath(worktree_dir or git_dir)

    def read_object(self, sha1: str) -> Optional[Tuple[str, bytes]]:
        """Read and decompress an object directly from .git/objects/."""
        if len(sha1) < 4:
            return None

        # Loose object path
        obj_path = os.path.join(self.git_dir, 'objects', sha1[:2], sha1[2:])
        if not os.path.isfile(obj_path):
            return None

        try:
            with open(obj_path, 'rb') as f:
                raw_data = f.read()
            decompressed = zlib.decompress(raw_data)
            null_pos = decompressed.find(b'\x00')
            if null_pos == -1:
                return None

            header = decompressed[:null_pos]
            content = decompressed[null_pos + 1:]
            obj_type = header.split(b' ')[0].decode('ascii', errors='ignore')
            return (obj_type, content)
        except Exception:
            return None

    def restore_from_index(self) -> int:
        """
        Parse .git/index and write out all tracked files directly into worktree_dir.
        Returns count of restored files.
        """
        index_path = os.path.join(self.git_dir, 'index')
        if not os.path.isfile(index_path):
            return 0

        try:
            with open(index_path, 'rb') as f:
                data = f.read()
        except Exception:
            return 0

        if len(data) < 12:
            return 0

        signature, version, entries = struct.unpack('>4sII', data[:12])
        if signature != b'DIRC':
            return 0

        offset = 12
        prev_name = b""
        restored = 0

        for _ in range(entries):
            if offset + 62 > len(data):
                break

            # Entry fields
            mode = struct.unpack('>I', data[offset + 24:offset + 28])[0]
            sha1 = data[offset + 40:offset + 60].hex()
            flags = struct.unpack('>H', data[offset + 60:offset + 62])[0]
            is_extended = (flags & 0x4000) != 0 and version >= 3
            fixed_len = 64 if is_extended else 62

            if offset + fixed_len > len(data):
                break

            if version == 4:
                pos = offset + fixed_len
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
                name_bytes = prev_name[:prefix_len] + suffix
                prev_name = name_bytes
                offset = nul_pos + 1
            else:
                nul_pos = data.find(b'\x00', offset + fixed_len)
                if nul_pos == -1:
                    break
                actual_name_length = nul_pos - (offset + fixed_len)
                name_bytes = data[offset + fixed_len:nul_pos]
                prev_name = name_bytes
                entry_len = fixed_len + actual_name_length
                entry_len += 8 - (entry_len % 8)
                offset += entry_len

            try:
                rel_path = name_bytes.decode('utf-8', errors='replace')
            except Exception:
                rel_path = name_bytes.decode('latin-1', errors='replace')

            # Prevent directory traversal attacks
            if rel_path.startswith('/') or '..' in rel_path.split('/'):
                continue

            obj = self.read_object(sha1)
            if not obj or obj[0] != 'blob':
                continue

            dest_path = os.path.join(self.worktree_dir, rel_path)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            try:
                with open(dest_path, 'wb') as f:
                    f.write(obj[1])

                # Set executable mode if 100755
                if (mode & 0o111) != 0:
                    try:
                        os.chmod(dest_path, 0o755)
                    except Exception:
                        pass
                restored += 1
            except Exception:
                pass

        return restored

    def restore_tree_recursive(self, tree_sha: str, current_dir: str) -> int:
        """Recursively extract files from a git tree object."""
        obj = self.read_object(tree_sha)
        if not obj or obj[0] != 'tree':
            return 0

        entries = GitParser.parse_tree(obj[1])
        restored = 0

        for entry in entries:
            name = entry.name
            if name.startswith('/') or '..' in name.split('/'):
                continue

            item_path = os.path.join(current_dir, name)

            if entry.is_dir:
                os.makedirs(item_path, exist_ok=True)
                restored += self.restore_tree_recursive(entry.sha1, item_path)
            else:
                blob_obj = self.read_object(entry.sha1)
                if blob_obj and blob_obj[0] == 'blob':
                    os.makedirs(os.path.dirname(item_path), exist_ok=True)
                    try:
                        with open(item_path, 'wb') as f:
                            f.write(blob_obj[1])
                        if entry.mode == '100755':
                            try:
                                os.chmod(item_path, 0o755)
                            except Exception:
                                pass
                        restored += 1
                    except Exception:
                        pass

        return restored

    def unpack_packfiles(self) -> int:
        """If pack files were downloaded, unpack them to loose objects using git unpack-objects."""
        pack_dir = os.path.join(self.git_dir, 'objects', 'pack')
        if not os.path.isdir(pack_dir):
            return 0

        unpacked = 0
        for fname in os.listdir(pack_dir):
            if fname.endswith('.pack'):
                pack_path = os.path.join(pack_dir, fname)
                try:
                    with open(pack_path, 'rb') as f:
                        proc = subprocess.run(
                            ['git', 'unpack-objects'],
                            cwd=self.git_dir if os.path.basename(self.git_dir) != '.git' else os.path.dirname(self.git_dir),
                            stdin=f,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=30
                        )
                        if proc.returncode == 0:
                            unpacked += 1
                except (FileNotFoundError, subprocess.SubprocessError):
                    pass

        return unpacked

    def auto_restore(self) -> int:
        """
        Main entry point for repository recovery.
        Tries Git CLI first, then falls back to internal pure-Python extractor.
        """
        # Step 1: Unpack packfiles if any
        self.unpack_packfiles()

        # Step 2: Try Git CLI native checkout if git command exists
        try:
            proc = subprocess.run(
                ['git', 'checkout', '-f'],
                cwd=self.worktree_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15
            )
            if proc.returncode == 0:
                # Count files created in worktree
                count = sum(len(files) for _, _, files in os.walk(self.worktree_dir) if '.git' not in _)
                return count
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

        # Step 3: Pure Python extraction from .git/index
        count = self.restore_from_index()
        if count > 0:
            return count

        # Step 4: If index had no files, restore from latest commit tree
        head_path = os.path.join(self.git_dir, 'HEAD')
        if os.path.isfile(head_path):
            try:
                with open(head_path, 'r', errors='ignore') as f:
                    head_content = f.read().strip()
                
                commit_sha = None
                if head_content.startswith('ref: '):
                    ref_rel = head_content[5:].strip()
                    ref_file = os.path.join(self.git_dir, ref_rel)
                    if os.path.isfile(ref_file):
                        with open(ref_file, 'r') as rf:
                            commit_sha = rf.read().strip()
                elif len(head_content) == 40:
                    commit_sha = head_content

                if commit_sha:
                    obj = self.read_object(commit_sha)
                    if obj and obj[0] == 'commit':
                        cinfo = GitParser.parse_commit(obj[1])
                        if cinfo.tree:
                            return self.restore_tree_recursive(cinfo.tree, self.worktree_dir)
            except Exception:
                pass

        return 0
