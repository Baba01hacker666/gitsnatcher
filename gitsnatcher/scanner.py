import os
import re
import zlib
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from .ui import Colors, log_msg


@dataclass
class Finding:
    category: str
    rule: str
    match: str
    location: str
    severity: str = "HIGH"


SECRET_RULES = [
    ("AWS Access Key", r'\bAKIA[0-9A-Z]{16}\b', "HIGH"),
    ("AWS Secret Key", r'(?i)aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "CRITICAL"),
    ("GitHub Token", r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b', "CRITICAL"),
    ("GitHub Fine-Grained Token", r'\bgithub_pat_[0-9a-zA-Z_]{82}\b', "CRITICAL"),
    ("GitLab Token", r'\bglpat-[0-9a-zA-Z\-]{20,}\b', "CRITICAL"),
    ("OpenAI API Key", r'\bsk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,}\b', "HIGH"),
    ("Anthropic API Key", r'\bsk-ant-[a-zA-Z0-9_\-]{40,}\b', "HIGH"),
    ("Google API Key", r'\bAIza[0-9A-Za-z\-_]{35}\b', "HIGH"),
    ("Google Service Account Key", r'"type":\s*"service_account"', "CRITICAL"),
    ("Slack Token", r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b', "HIGH"),
    ("Slack Webhook", r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "MEDIUM"),
    ("Stripe Secret Key", r'\b[sr]k_live_[0-9a-zA-Z]{24,34}\b', "CRITICAL"),
    ("SendGrid API Key", r'\bSG\.[a-zA-Z0-9_\-\.]{66}\b', "HIGH"),
    ("Twilio API Key", r'\bSK[0-9a-fA-F]{32}\b', "HIGH"),
    ("RSA/SSH Private Key", r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----', "CRITICAL"),
    ("Database Connection URI", r'(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_]+:[^@\s\'"<>]+@[a-zA-Z0-9_\.\-]+(?::[0-9]+)?/[a-zA-Z0-9_\.\-]+', "CRITICAL"),
    ("JSON Web Token (JWT)", r'\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b', "MEDIUM"),
    ("Generic Password/Secret", r'(?i)(?:password|passwd|secret|api_key|apikey|auth_token)\s*[:=]\s*["\']([^\s\'"]{8,64})["\']', "MEDIUM"),
]

SENSITIVE_FILENAMES = {
    '.env', '.env.local', '.env.production', '.env.staging', '.env.dev',
    'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa',
    'wp-config.php', 'configuration.php', 'config.inc.php',
    'database.yml', 'settings.py', 'local_settings.py',
    'credentials.json', 'service-account.json', 'client_secrets.json',
    '.npmrc', '.pypirc', '.dockercfg', 'htpasswd', '.htpasswd',
}


class SecretScanner:
    """Scans reconstructed git repositories, objects, and trees for leaked secrets."""

    def __init__(self, git_dir: str):
        if os.path.basename(os.path.normpath(git_dir)) == '.git':
            self.git_dir = os.path.abspath(git_dir)
        else:
            self.git_dir = os.path.abspath(os.path.join(git_dir, '.git')) if os.path.exists(os.path.join(git_dir, '.git')) else os.path.abspath(git_dir)
        self.findings: List[Finding] = []

    def scan_text(self, text: str, location: str):
        """Scan a piece of text against all secret patterns."""
        if not text:
            return

        for rule_name, pattern, severity in SECRET_RULES:
            matches = re.finditer(pattern, text)
            for m in matches:
                matched_val = m.group(0)
                # Obfuscate middle part of sensitive match
                if len(matched_val) > 8:
                    masked = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:]
                else:
                    masked = matched_val[:2] + "****"

                finding = Finding(
                    category="Credential",
                    rule=rule_name,
                    match=masked,
                    location=location,
                    severity=severity
                )
                self.findings.append(finding)

    def scan_all_objects(self) -> List[Finding]:
        """Scan all loose git objects and index in .git directory."""
        self.findings.clear()
        objects_dir = os.path.join(self.git_dir, 'objects')
        if not os.path.isdir(objects_dir):
            return self.findings

        # 1. Scan objects
        for root, _, files in os.walk(objects_dir):
            if 'pack' in root or 'info' in root:
                continue
            for fname in files:
                obj_sha = os.path.basename(root) + fname
                obj_path = os.path.join(root, fname)
                try:
                    with open(obj_path, 'rb') as f:
                        data = f.read()
                    decompressed = zlib.decompress(data)
                    null_pos = decompressed.find(b'\x00')
                    if null_pos != -1:
                        header = decompressed[:null_pos]
                        content = decompressed[null_pos + 1:]
                        obj_type = header.split(b' ')[0].decode('ascii', errors='ignore')
                        if obj_type in ('blob', 'commit'):
                            try:
                                text = content.decode('utf-8', errors='ignore')
                                self.scan_text(text, f"Object {obj_type}:{obj_sha[:8]}")
                            except Exception:
                                pass
                except Exception:
                    continue

        # 2. Scan sensitive filenames in the worktree if present
        worktree_dir = os.path.dirname(self.git_dir)
        for root, _, files in os.walk(worktree_dir):
            if '.git' in root:
                continue
            for fname in files:
                if fname.lower() in SENSITIVE_FILENAMES or fname.startswith('.env'):
                    rel = os.path.relpath(os.path.join(root, fname), worktree_dir)
                    self.findings.append(Finding(
                        category="Sensitive File",
                        rule="Exposed Configuration / Key File",
                        match=fname,
                        location=rel,
                        severity="HIGH"
                    ))

        return self.findings

    def print_report(self):
        """Print formatted findings table."""
        if not self.findings:
            log_msg("success", "Secret scan completed: No obvious credentials or sensitive files discovered.")
            return

        print("\n" + "=" * 60)
        print(f"{Colors.BOLD}{Colors.FAIL}=== SECURITY & SECRET SCAN FINDINGS ({len(self.findings)} Detected) ==={Colors.ENDC}")
        print("=" * 60)

        for idx, finding in enumerate(self.findings, 1):
            sev_color = Colors.FAIL if finding.severity == "CRITICAL" else (Colors.WARNING if finding.severity == "HIGH" else Colors.OKBLUE)
            print(f"[{idx}] {sev_color}[{finding.severity}]{Colors.ENDC} {Colors.BOLD}{finding.rule}{Colors.ENDC}")
            print(f"    Location : {finding.location}")
            print(f"    Match    : {Colors.DIM}{finding.match}{Colors.ENDC}")
            print("-" * 60)
