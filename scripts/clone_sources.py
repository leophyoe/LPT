#!/usr/bin/env python3
"""Clones upstream security repositories into source/<category>/<name> with shallow history."""

import os
import subprocess
import sys
from pathlib import Path

REPOSITORIES = [
    # Batch 1 & Batch 2 Repositories
    ("network", "nmap", "https://github.com/nmap/nmap.git"),
    ("network", "wireshark", "https://github.com/wireshark/wireshark.git"),
    ("network", "impacket", "https://github.com/fortra/impacket.git"),
    ("network", "NetExec", "https://github.com/Pennyw0rth/NetExec.git"),
    ("web", "zaproxy", "https://github.com/zaproxy/zaproxy.git"),
    ("web", "sqlmap", "https://github.com/sqlmapproject/sqlmap.git"),
    ("web", "ffuf", "https://github.com/ffuf/ffuf.git"),
    ("web", "nikto", "https://github.com/sullo/nikto.git"),
    ("web", "wafw00f", "https://github.com/EnableSecurity/wafw00f.git"),
    ("vulnerability", "nuclei", "https://github.com/projectdiscovery/nuclei.git"),
    ("mobile", "MobSF", "https://github.com/MobSF/Mobile-Security-Framework-MobSF.git"),
    ("mobile", "jadx", "https://github.com/skylot/jadx.git"),
    ("mobile", "frida", "https://github.com/frida/frida.git"),
    ("mobile", "objection", "https://github.com/sensepost/objection.git"),
    ("mobile", "Apktool", "https://github.com/iBotPeaches/Apktool.git"),
    ("reverse_engineering", "ghidra", "https://github.com/NationalSecurityAgency/ghidra.git"),
    ("reverse_engineering", "radare2", "https://github.com/radareorg/radare2.git"),
    ("code_security", "semgrep", "https://github.com/semgrep/semgrep.git"),
    ("code_security", "bandit", "https://github.com/PyCQA/bandit.git"),
    ("code_security", "gitleaks", "https://github.com/gitleaks/gitleaks.git"),
    ("code_security", "trivy", "https://github.com/aquasecurity/trivy.git"),
    ("cloud", "prowler", "https://github.com/prowler-cloud/prowler.git"),
    ("cloud", "ScoutSuite", "https://github.com/nccgroup/ScoutSuite.git"),
    ("system", "volatility3", "https://github.com/volatilityfoundation/volatility3.git"),
    ("system", "autopsy", "https://github.com/sleuthkit/autopsy.git"),
]


def main():
    root = Path(__file__).resolve().parent.parent
    source_dir = root / "source"
    print(f"Target root: {root}")
    print(f"Total repositories to collect: {len(REPOSITORIES)}")
    print("=" * 60)

    success_count = 0
    skip_count = 0
    fail_count = 0

    for category, name, url in REPOSITORIES:
        target_path = source_dir / category / name
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if (target_path / ".git").is_dir():
            print(f"[SKIP] {category}/{name} already exists.")
            skip_count += 1
            continue

        print(f"[CLONING] {category}/{name} from {url} ...")
        cmd = ["git", "clone", "--depth", "1", url, str(target_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if res.returncode == 0:
                print(f"[SUCCESS] {category}/{name} cloned successfully.")
                success_count += 1
            else:
                print(f"[FAILED] {category}/{name}: {res.stderr.strip()}")
                fail_count += 1
        except subprocess.TimeoutExpired:
            print(f"[TIMEOUT] {category}/{name} timed out after 600s.")
            fail_count += 1
        except Exception as e:
            print(f"[ERROR] {category}/{name}: {e}")
            fail_count += 1

    print("=" * 60)
    print(f"Collection complete: {success_count} cloned, {skip_count} skipped, {fail_count} failed.")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

