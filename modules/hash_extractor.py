"""
Module 2: Hash Extractor
Demonstrates hash extraction from Linux /etc/shadow and Windows SAM (offline demo only).
For EDUCATIONAL and ETHICAL lab use only.
"""

import hashlib
import os
import re


# --- Sample data simulating what would be found in real environments ---

SAMPLE_SHADOW_ENTRIES = [
    "root:$6$rounds=5000$abc123salt$HashedPasswordHere111111111111111111111111111111111111111111111111111111111111111111111111:19000:0:99999:7:::",
    "alice:$6$saltalice$aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuvwxyzABCDE:19001:0:99999:7:::",
    "bob:$1$bobsalt$rjlSmXtBfO/VvX7Y9z8kQ.:19002:0:99999:7:::",
    "charlie:$5$charliesalt$WOaNQDvN8u1P3K56eAH.W7l.J9mFbZYfbO9Y7pUK3O7:19003:0:99999:7:::",
    "sysadmin:$6$adminsalt$Th1sIsAH4shedPasswordForDemoOnlyNot4RealUse111111111111111111111111111111111111111:19004:0:99999:7:::",
]

SAMPLE_SAM_ENTRIES = [
    {"user": "Administrator", "rid": 500, "lm_hash": "aad3b435b51404eeaad3b435b51404ee", "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
    {"user": "Guest",         "rid": 501, "lm_hash": "aad3b435b51404eeaad3b435b51404ee", "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
    {"user": "alice",         "rid": 1001, "lm_hash": "aad3b435b51404eeaad3b435b51404ee", "nt_hash": "8846f7eaee8fb117ad06bdd830b7586c"},
    {"user": "bob",           "rid": 1002, "lm_hash": "e52cac67419a9a224a3b108f3fa6cb6d", "nt_hash": "b4b9b02e6f09a9bd760f388b67351e2b"},
    {"user": "sysadmin",      "rid": 1003, "lm_hash": "aad3b435b51404eeaad3b435b51404ee", "nt_hash": "2b576acbe6bcfda7294d6bd18041b8fe"},
]

# Algorithm identifiers used in Linux shadow
SHADOW_ALGO_MAP = {
    "$1$":  "MD5",
    "$2$":  "Blowfish (bcrypt)",
    "$2a$": "Blowfish (bcrypt)",
    "$2b$": "Blowfish (bcrypt)",
    "$5$":  "SHA-256",
    "$6$":  "SHA-512",
    "$y$":  "yescrypt",
}


class HashExtractor:
    def __init__(self):
        self.extracted_hashes = []

    # -------------------------------------------------------
    # LINUX: /etc/shadow parser
    # -------------------------------------------------------
    def demo_linux_shadow(self):
        """
        Demonstrate parsing of Linux /etc/shadow file format.
        Uses sample data — does NOT touch real system files.
        """
        print("\n  [*] Linux /etc/shadow Hash Extraction (DEMO)")
        print("  " + "-" * 55)
        print(f"  {'Username':<12} {'Algorithm':<18} {'Salt':<18} {'Hash Preview'}")
        print("  " + "-" * 55)

        for entry in SAMPLE_SHADOW_ENTRIES:
            parts = entry.split(":")
            username = parts[0]
            hash_field = parts[1] if len(parts) > 1 else ""

            if hash_field in ("*", "!", "!!"):
                algo = "LOCKED / NO LOGIN"
                salt = "-"
                hash_preview = "-"
            else:
                algo = self._detect_shadow_algo(hash_field)
                salt, hash_preview = self._parse_shadow_hash(hash_field)

            print(f"  {username:<12} {algo:<18} {salt:<18} {hash_preview[:20]}...")
            self.extracted_hashes.append({
                "source": "linux",
                "user": username,
                "algo": algo,
                "raw": hash_field,
            })

        print(f"\n  [✓] Extracted {len(SAMPLE_SHADOW_ENTRIES)} shadow entries (demo data)")
        print("\n  NOTE: Real extraction requires: sudo cat /etc/shadow")
        print("        (only on systems you are AUTHORIZED to access)")

    def _detect_shadow_algo(self, hash_field: str) -> str:
        for prefix, name in SHADOW_ALGO_MAP.items():
            if hash_field.startswith(prefix):
                return name
        return "Unknown/DES"

    def _parse_shadow_hash(self, hash_field: str) -> tuple:
        """Extract salt and hash portion from shadow hash string."""
        # Format: $id$[rounds=N$]salt$hash
        parts = hash_field.split("$")
        if len(parts) >= 4:
            # Check for rounds= prefix
            if parts[2].startswith("rounds="):
                salt = parts[3] if len(parts) > 3 else "?"
                hsh = parts[4] if len(parts) > 4 else "?"
            else:
                salt = parts[2]
                hsh = parts[3]
            return salt[:16], hsh
        return "?", hash_field[:20]

    # -------------------------------------------------------
    # WINDOWS: SAM database demo
    # -------------------------------------------------------
    def demo_windows_sam(self):
        """
        Demonstrate Windows SAM database structure.
        Shows NT hash format (NTLM) — demo data only.
        """
        print("\n\n  [*] Windows SAM Database Hash Extraction (DEMO)")
        print("  " + "-" * 65)
        print(f"  {'Username':<16} {'RID':<6} {'LM Hash':<36} {'NT Hash'}")
        print("  " + "-" * 65)

        for entry in SAMPLE_SAM_ENTRIES:
            lm_empty = " [empty]" if entry["lm_hash"] == "aad3b435b51404eeaad3b435b51404ee" else ""
            nt_empty = " [blank pwd]" if entry["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0" else ""
            print(f"  {entry['user']:<16} {entry['rid']:<6} {entry['lm_hash']}{lm_empty}")
            print(f"  {'':>22} NT: {entry['nt_hash']}{nt_empty}")
            self.extracted_hashes.append({
                "source": "windows",
                "user": entry["user"],
                "algo": "NTLM",
                "raw": entry["nt_hash"],
            })

        print(f"\n  [✓] Extracted {len(SAMPLE_SAM_ENTRIES)} SAM entries (demo data)")
        print("\n  Real extraction method (offline, from another OS):")
        print("    reg save HKLM\\SAM    C:\\sam.hive")
        print("    reg save HKLM\\SYSTEM C:\\system.hive")
        print("    Then use: secretsdump.py / impacket (authorized systems only)")

    # -------------------------------------------------------
    # Hash generation utilities (for lab use)
    # -------------------------------------------------------
    def generate_hash(self, password: str, algo: str = "sha256") -> dict:
        """Generate hashes of a password using multiple algorithms (lab utility)."""
        pwd_bytes = password.encode()
        results = {
            "md5":    hashlib.md5(pwd_bytes).hexdigest(),
            "sha1":   hashlib.sha1(pwd_bytes).hexdigest(),
            "sha256": hashlib.sha256(pwd_bytes).hexdigest(),
            "sha512": hashlib.sha512(pwd_bytes).hexdigest(),
            "ntlm":   self._ntlm_hash(password),
        }
        return results

    def _ntlm_hash(self, password: str) -> str:
        """Compute NTLM (NT) hash using pure-Python MD4 (avoids OpenSSL legacy dependency)."""
        return self._md4(password.encode("utf-16-le"))

    def _md4(self, data: bytes) -> str:
        """Pure Python MD4 (RFC 1320) for NTLM hashing."""
        import struct

        def lr(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
        def F(x, y, z): return (x & y) | (~x & z)
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z

        orig_len = len(data)
        data = bytearray(data)
        data.append(0x80)
        data += b'\x00' * ((55 - orig_len) % 64)
        data += struct.pack('<Q', orig_len * 8)

        a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

        for i in range(0, len(data), 64):
            X = struct.unpack('<16I', data[i:i+64])
            aa, bb, cc, dd = a, b, c, d
            s1 = [3, 7, 11, 19]
            for j in range(16):
                k = j
                aa = lr((aa + F(bb, cc, dd) + X[k]) & 0xFFFFFFFF, s1[j % 4])
                aa, bb, cc, dd = dd, aa, bb, cc
            s2 = [3, 5, 9, 13]
            for j, k in enumerate([0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]):
                aa = lr((aa + G(bb, cc, dd) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[j % 4])
                aa, bb, cc, dd = dd, aa, bb, cc
            s3 = [3, 9, 11, 15]
            for j, k in enumerate([0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]):
                aa = lr((aa + H(bb, cc, dd) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[j % 4])
                aa, bb, cc, dd = dd, aa, bb, cc
            a = (a + aa) & 0xFFFFFFFF
            b = (b + bb) & 0xFFFFFFFF
            c = (c + cc) & 0xFFFFFFFF
            d = (d + dd) & 0xFFFFFFFF

        return struct.pack('<4I', a, b, c, d).hex()

    def show_hash_demo(self, password: str = "Password123"):
        """Show all hash types for a sample password."""
        print(f"\n  [*] Hash generation demo for: '{password}'")
        hashes = self.generate_hash(password)
        for algo, value in hashes.items():
            print(f"    {algo.upper():<8}: {value}")
