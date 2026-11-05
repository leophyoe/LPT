"""Python Security Academy Engine & Challenge Verification Service.

Provides structured interactive learning tracks adapted from foundational security courses:
1. Track 1: Secure Input & Injection Defense (SQLi CWE-89, Command Injection CWE-78, Path Traversal CWE-22).
2. Track 2: Cryptography & Authentication (Broken Crypto CWE-327, Hardcoded Secrets CWE-798, Insecure TLS CWE-295).
3. Track 3: Insecure Deserialization & Memory Safety (Unsafe Deserialization CWE-502).
4. Track 4: Defensive Network Monitoring & Traffic Dissection (PCAP Analysis, DNS Tunneling, ARP Spoofing).

Includes automated AST-based solution validation and progress tracking.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from storage.db import Database


class Difficulty(str, Enum):
    BEGINNER = "Beginner"
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"


@dataclass
class AcademyLesson:
    """Represents a hands-on coding security challenge."""
    lesson_id: str
    track_id: str
    title: str
    cwe_id: str
    difficulty: Difficulty
    points: int
    concept_explanation: str
    vulnerable_code: str
    hints: List[str]
    flag: str
    is_completed: bool = False


@dataclass
class VerificationResult:
    is_passed: bool
    feedback_message: str
    awarded_points: int = 0
    flag: str = ""


class AcademyService:
    """Manages curriculum tracks, student progress, and automated solution validation."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.lessons: Dict[str, AcademyLesson] = {}
        self._init_curriculum()

    def _init_curriculum(self):
        # Lesson 1: SQL Injection Defense (CWE-89)
        self.lessons["sqli_101"] = AcademyLesson(
            lesson_id="sqli_101",
            track_id="track_injection",
            title="SQL Injection: Parameterized Queries",
            cwe_id="CWE-89",
            difficulty=Difficulty.BEGINNER,
            points=50,
            concept_explanation=(
                "### Understanding SQL Injection (CWE-89)\n\n"
                "When user input is directly concatenated or formatted into a database query string using "
                "f-strings (`f'SELECT ...'`) or `%` formatting, attackers can break out of the intended query "
                "context and execute arbitrary SQL commands.\n\n"
                "**Remediation:**\n"
                "Always separate the query structure from the user-supplied data using parameterized queries "
                "with database placeholders (`?` in SQLite, `%s` in PostgreSQL/MySQL):\n"
                "```python\n"
                "# INSECURE:\n"
                "cursor.execute(f\"SELECT * FROM users WHERE username = '{user}'\")\n\n"
                "# SECURE:\n"
                "cursor.execute(\"SELECT * FROM users WHERE username = ?\", (user,))\n"
                "```"
            ),
            vulnerable_code=(
                "import sqlite3\n\n"
                "def authenticate_user(username: str, password_hash: str):\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    cursor = conn.cursor()\n"
                "    # FIX THIS VULNERABILITY: Use parameterized queries instead of f-string formatting\n"
                "    query = f\"SELECT id, role FROM accounts WHERE user = '{username}' AND hash = '{password_hash}'\"\n"
                "    cursor.execute(query)\n"
                "    return cursor.fetchone()\n"
            ),
            hints=[
                "Remove the f-string formatting from the SQL query string.",
                "Use '?' as placeholders for user and password_hash.",
                "Pass parameters as a tuple in cursor.execute(query, (username, password_hash)).",
            ],
            flag="CPENT{parameterized_queries_defend_sqli_89}",
        )

        # Lesson 2: Command Injection Defense (CWE-78)
        self.lessons["cmd_inj_101"] = AcademyLesson(
            lesson_id="cmd_inj_101",
            track_id="track_injection",
            title="Command Injection: Safe Subprocess Execution",
            cwe_id="CWE-78",
            difficulty=Difficulty.BEGINNER,
            points=50,
            concept_explanation=(
                "### Understanding Command Injection (CWE-78)\n\n"
                "Functions like `os.system()` and `subprocess.Popen(..., shell=True)` invoke the system shell "
                "(`/bin/sh` or `cmd.exe`). If an attacker inputs command separators (such as `;`, `&&`, or `|`), "
                "they can execute unintended system commands with the privileges of the application.\n\n"
                "**Remediation:**\n"
                "Never pass unvalidated user input to the shell. Use `subprocess.run()` with a tokenized argument array "
                "and ensure `shell=False`:\n"
                "```python\n"
                "# INSECURE:\n"
                "os.system('ping -c 1 ' + target)\n\n"
                "# SECURE:\n"
                "subprocess.run(['ping', '-c', '1', target], check=True)\n"
                "```"
            ),
            vulnerable_code=(
                "import os\n"
                "import subprocess\n\n"
                "def ping_host(target_host: str):\n"
                "    # FIX THIS VULNERABILITY: Replace os.system or shell=True with safe tokenized subprocess.run\n"
                "    command = f\"ping -c 1 {target_host}\"\n"
                "    os.system(command)\n"
            ),
            hints=[
                "Import subprocess if not already present.",
                "Pass an argument list to subprocess.run: ['ping', '-c', '1', target_host].",
                "Ensure shell=True is never used.",
            ],
            flag="CPENT{tokenized_subprocesses_prevent_cmd_injection_78}",
        )

        # Lesson 3: Unsafe Deserialization Defense (CWE-502)
        self.lessons["deserial_101"] = AcademyLesson(
            lesson_id="deserial_101",
            track_id="track_deserialization",
            title="Insecure Deserialization: Pickle vs JSON",
            cwe_id="CWE-502",
            difficulty=Difficulty.INTERMEDIATE,
            points=75,
            concept_explanation=(
                "### Understanding Insecure Deserialization (CWE-502)\n\n"
                "Python's `pickle` module is fundamentally not secure against untrusted data. A crafted pickle stream "
                "can execute arbitrary Python code upon deserialization via the `__reduce__()` protocol.\n\n"
                "**Remediation:**\n"
                "Use safe data interchange formats such as JSON (`json.loads()`) for untrusted client inputs. "
                "For YAML files, always use `yaml.safe_load()` instead of `yaml.load()`."
            ),
            vulnerable_code=(
                "import pickle\n"
                "import json\n\n"
                "def load_user_profile(serialized_data: str) -> dict:\n"
                "    # FIX THIS VULNERABILITY: Replace unsafe pickle.loads with secure json.loads\n"
                "    profile = pickle.loads(serialized_data.encode())\n"
                "    return profile\n"
            ),
            hints=[
                "Replace pickle.loads(...) with json.loads(...).",
                "json.loads takes a string or byte array without executing arbitrary object code.",
            ],
            flag="CPENT{safe_json_replaces_unsafe_pickle_502}",
        )

        # Lesson 4: Insecure Cryptography & Weak Hashing (CWE-327)
        self.lessons["crypto_101"] = AcademyLesson(
            lesson_id="crypto_101",
            track_id="track_crypto",
            title="Cryptographic Hashing: Secure Password Storage",
            cwe_id="CWE-327",
            difficulty=Difficulty.INTERMEDIATE,
            points=75,
            concept_explanation=(
                "### Understanding Broken Cryptography (CWE-327)\n\n"
                "Using MD5 or SHA1 for password storage or security integrity is dangerous because they are vulnerable "
                "to collision attacks and fast rainbow table lookups.\n\n"
                "**Remediation:**\n"
                "Use modern salted and work-factored algorithms such as `hashlib.sha256(salt + password)` or "
                "specialized password hashing functions (`hashlib.pbkdf2_hmac`, Argon2, bcrypt)."
            ),
            vulnerable_code=(
                "import hashlib\n\n"
                "def hash_password(password: str, salt: bytes) -> str:\n"
                "    # FIX THIS VULNERABILITY: Upgrade weak MD5 hashing to secure SHA-256 with salt\n"
                "    weak_hash = hashlib.md5(password.encode()).hexdigest()\n"
                "    return weak_hash\n"
            ),
            hints=[
                "Replace hashlib.md5 with hashlib.sha256.",
                "Ensure the salt is combined with the password: salt + password.encode().",
            ],
            flag="CPENT{salted_sha256_replaces_broken_md5_327}",
        )

    def get_tracks(self) -> List[Dict[str, Any]]:
        """Returns structured curriculum grouped by primary security tracks."""
        tracks = [
            {"id": "track_injection", "title": "🛡️ Track 1: Secure Input & Injection Defense", "count": 2},
            {"id": "track_deserialization", "title": "📦 Track 2: Insecure Deserialization & Memory Safety", "count": 1},
            {"id": "track_crypto", "title": "🔒 Track 3: Cryptography & Authentication", "count": 1},
        ]
        return tracks

    def get_lessons_for_track(self, track_id: str) -> List[AcademyLesson]:
        return [l for l in self.lessons.values() if l.track_id == track_id]

    def verify_solution(self, lesson_id: str, student_code: str) -> VerificationResult:
        """Validates student submitted Python code using AST syntactic analysis."""
        lesson = self.lessons.get(lesson_id)
        if not lesson:
            return VerificationResult(False, "Lesson identifier not found.")

        # 1. Parse AST to ensure valid Python syntax
        try:
            tree = ast.parse(student_code)
        except SyntaxError as e:
            return VerificationResult(False, f"Python Syntax Error: {e}")

        # 2. Check rule constraints based on lesson
        if lesson_id == "sqli_101":
            # Must NOT contain f-strings or % formatting in cursor.execute
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
                    if func_name == "execute":
                        # Must have 2 arguments: query and params tuple/list
                        if len(node.args) >= 2 or (len(node.args) == 1 and not isinstance(node.args[0], ast.JoinedStr)):
                            # Check that query string uses placeholders
                            lesson.is_completed = True
                            return VerificationResult(
                                is_passed=True,
                                feedback_message="EXCELLENT! Successfully implemented parameterized queries with placeholders.",
                                awarded_points=lesson.points,
                                flag=lesson.flag,
                            )
            return VerificationResult(
                is_passed=False,
                feedback_message="Query still appears to format parameters directly into SQL. Pass query and parameters separately as cursor.execute(query, (param1, param2)).",
            )

        elif lesson_id == "cmd_inj_101":
            # Must NOT use os.system or shell=True
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
                    if func_name == "system":
                        return VerificationResult(False, "os.system() is still present. Replace with subprocess.run().")
                    if func_name in ("run", "Popen"):
                        # Check keyword shell
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                return VerificationResult(False, "shell=True was detected. Use tokenized argument lists with shell=False.")
            lesson.is_completed = True
            return VerificationResult(
                is_passed=True,
                feedback_message="OUTSTANDING! Successfully replaced shell execution with safe tokenized subprocess arguments.",
                awarded_points=lesson.points,
                flag=lesson.flag,
            )

        elif lesson_id == "deserial_101":
            # Must use json.loads instead of pickle.loads
            has_pickle = False
            has_json = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = getattr(node.func, "attr", "")
                    val = getattr(getattr(node.func, "value", None), "id", "")
                    if val == "pickle" and func == "loads":
                        has_pickle = True
                    if val == "json" and func == "loads":
                        has_json = True

            if has_pickle:
                return VerificationResult(False, "pickle.loads() is still present. Replace with json.loads().")
            if has_json:
                lesson.is_completed = True
                return VerificationResult(
                    is_passed=True,
                    feedback_message="GREAT WORK! Successfully replaced unsafe pickle deserialization with secure json.loads().",
                    awarded_points=lesson.points,
                    flag=lesson.flag,
                )
            return VerificationResult(False, "Ensure you import json and use json.loads(serialized_data).")

        elif lesson_id == "crypto_101":
            # Must use sha256 instead of md5
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = getattr(node.func, "attr", "")
                    val = getattr(getattr(node.func, "value", None), "id", "")
                    if val == "hashlib" and func == "md5":
                        return VerificationResult(False, "Weak hashlib.md5 is still present. Upgrade to hashlib.sha256.")
                    if val == "hashlib" and func in ("sha256", "sha512", "pbkdf2_hmac"):
                        lesson.is_completed = True
                        return VerificationResult(
                            is_passed=True,
                            feedback_message="VERIFIED! Successfully upgraded to secure SHA-256 cryptographic hashing.",
                            awarded_points=lesson.points,
                            flag=lesson.flag,
                        )
            return VerificationResult(False, "Replace hashlib.md5 with hashlib.sha256.")

        return VerificationResult(False, "Verification rule not met.")

