"""High-Performance Binary-Indexed Cryptographic Hash Lookup Engine.

Inspired by the index-based lookup architecture in Micro-Degree-in-Python-Security,
reimplemented clean-room in pure Python 3 for CyberSecuritySuite.

Creates fixed-size 14-byte binary index files:
- 8 Bytes (64 bits): Big-endian integer prefix of the computed hash.
- 6 Bytes (48 bits): Little-endian file offset pointing directly to the word in the dictionary.

Enables O(log N) binary search on disk with virtually 0 RAM overhead, capable of
matching MD5, SHA-1, SHA-256, and NTLM hashes against multimillion-word dictionaries.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Callable, Generator, List, Optional, Tuple

RECORD_SIZE = 14  # 8 bytes hash prefix + 6 bytes offset


class HashLookupEngine:
    """Binary-indexed hash search and dictionary indexing engine."""

    SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "ntlm")

    @staticmethod
    def compute_hash(word: str, algorithm: str = "md5") -> bytes:
        """Computes raw binary hash for a given plaintext string."""
        alg = algorithm.lower().strip()
        data = word.encode("utf-8")
        if alg == "md5":
            return hashlib.md5(data).digest()
        elif alg == "sha1":
            return hashlib.sha1(data).digest()
        elif alg == "sha256":
            return hashlib.sha256(data).digest()
        elif alg == "ntlm":
            # NTLM is MD4 of UTF-16LE encoding
            return hashlib.new("md4", word.encode("utf-16le")).digest()
        else:
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Supported: {HashLookupEngine.SUPPORTED_ALGORITHMS}")

    @staticmethod
    def _pack_record(hash_bytes: bytes, file_offset: int) -> bytes:
        """Packs a 64-bit hash prefix and 48-bit file offset into 14 bytes."""
        prefix_int = struct.unpack(">Q", hash_bytes[:8])[0]
        offset_bytes = file_offset.to_bytes(6, byteorder="little", signed=False)
        return struct.pack(">Q", prefix_int) + offset_bytes

    @staticmethod
    def _unpack_record(data: bytes) -> Tuple[int, int]:
        """Unpacks 14-byte record into (prefix_int, file_offset)."""
        prefix_int = struct.unpack(">Q", data[:8])[0]
        offset = int.from_bytes(data[8:14], byteorder="little", signed=False)
        return prefix_int, offset

    @classmethod
    def create_index(
        cls,
        wordlist_path: str,
        index_path: str,
        algorithm: str = "md5",
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> int:
        """Generates a sorted binary index file from a wordlist dictionary.
        
        Returns the total number of indexed words.
        """
        wl_p = Path(wordlist_path)
        if not wl_p.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        records: List[Tuple[int, int]] = []
        with open(wl_p, "rb") as f:
            offset = f.tell()
            line = f.readline()
            while line:
                word = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
                if word:
                    h_bytes = cls.compute_hash(word, algorithm)
                    prefix_int = struct.unpack(">Q", h_bytes[:8])[0]
                    records.append((prefix_int, offset))
                offset = f.tell()
                line = f.readline()

        # Sort records by hash prefix for binary search
        records.sort(key=lambda r: r[0])

        # Write to index file
        idx_p = Path(index_path)
        idx_p.parent.mkdir(parents=True, exist_ok=True)
        with open(idx_p, "wb") as out:
            for prefix_int, off in records:
                offset_bytes = off.to_bytes(6, byteorder="little", signed=False)
                out.write(struct.pack(">Q", prefix_int) + offset_bytes)

        if progress_callback:
            progress_callback(len(records), len(records))

        return len(records)

    @classmethod
    def lookup_hash(
        cls,
        hash_hex: str,
        wordlist_path: str,
        index_path: str,
        algorithm: str = "md5",
    ) -> Optional[str]:
        """Performs disk-based binary search to find plaintext match for a hash."""
        clean_hex = hash_hex.strip().lower()
        try:
            target_bytes = bytes.fromhex(clean_hex)
        except ValueError:
            return None

        if len(target_bytes) < 8:
            return None

        target_prefix = struct.unpack(">Q", target_bytes[:8])[0]

        idx_p = Path(index_path)
        wl_p = Path(wordlist_path)
        if not idx_p.exists() or not wl_p.exists():
            return None

        file_size = idx_p.stat().st_size
        num_records = file_size // RECORD_SIZE
        if num_records == 0:
            return None

        with open(idx_p, "rb") as idx_file, open(wl_p, "rb") as wl_file:
            low = 0
            high = num_records - 1
            match_index: Optional[int] = None

            while low <= high:
                mid = (low + high) // 2
                idx_file.seek(mid * RECORD_SIZE)
                data = idx_file.read(RECORD_SIZE)
                if len(data) < RECORD_SIZE:
                    break

                curr_prefix, _ = cls._unpack_record(data)
                if curr_prefix == target_prefix:
                    match_index = mid
                    break
                elif curr_prefix < target_prefix:
                    low = mid + 1
                else:
                    high = mid - 1

            if match_index is None:
                return None

            # Check matching and adjacent records in case of 64-bit prefix collisions
            start_scan = max(0, match_index - 50)
            end_scan = min(num_records, match_index + 50)
            idx_file.seek(start_scan * RECORD_SIZE)

            for _ in range(start_scan, end_scan):
                chunk = idx_file.read(RECORD_SIZE)
                if len(chunk) < RECORD_SIZE:
                    break
                p_int, offset = cls._unpack_record(chunk)
                if p_int == target_prefix:
                    wl_file.seek(offset)
                    cand_line = wl_file.readline().rstrip(b"\r\n").decode("utf-8", errors="replace")
                    cand_hash = cls.compute_hash(cand_line, algorithm)
                    if cand_hash.hex().lower() == clean_hex:
                        return cand_line
                elif p_int > target_prefix:
                    break

        return None

