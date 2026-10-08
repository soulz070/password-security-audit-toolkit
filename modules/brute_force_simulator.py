"""
Module 3: Brute-Force Simulator
Simulates brute-force cracking attempts and estimates time-to-crack.
For EDUCATIONAL and ETHICAL lab use only.
"""

import string
import math
import time
import itertools


# Estimated hashing speeds (hashes/second) for modern hardware
# These reflect real-world GPU cracking benchmarks
CRACKING_SPEEDS = {
    "MD5":       10_000_000_000,   # 10 billion/sec (GPU)
    "SHA1":       3_000_000_000,   #  3 billion/sec
    "SHA256":     1_000_000_000,   #  1 billion/sec
    "SHA512":       500_000_000,   # 500 million/sec
    "NTLM":      10_000_000_000,   # 10 billion/sec (GPU)
    "bcrypt":            15_000,   # 15k/sec (slow by design)
    "SHA512crypt":       20_000,   # 20k/sec (Linux $6$)
}

# Character sets for brute-force search space
CHARSETS = {
    "digits":       string.digits,                              # 10
    "lowercase":    string.ascii_lowercase,                     # 26
    "uppercase":    string.ascii_uppercase,                     # 26
    "alpha":        string.ascii_letters,                       # 52
    "alphanum":     string.ascii_letters + string.digits,       # 62
    "full":         string.ascii_letters + string.digits + string.punctuation,  # 95
}

# Common wordlist used for dictionary attack simulation
COMMON_DICT = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "master", "dragon",
    "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "princess", "welcome", "shadow", "superman", "michael",
    "football", "charlie", "donald", "password1", "hello",
]


def _human_time(seconds: float) -> str:
    """Convert seconds to a human-readable time string."""
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 86400 * 30:
        return f"{seconds/86400:.1f} days"
    if seconds < 86400 * 365:
        return f"{seconds/(86400*30):.1f} months"
    years = seconds / (86400 * 365)
    if years < 1_000_000:
        return f"{years:,.1f} years"
    return "millions+ years (practically uncrackable)"


def _search_space(password: str) -> tuple:
    """Determine the character pool and calculate search space size."""
    pool = 0
    breakdown = []
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
        breakdown.append("lowercase(26)")
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
        breakdown.append("UPPERCASE(26)")
    if any(c in string.digits for c in password):
        pool += 10
        breakdown.append("digits(10)")
    if any(c in string.punctuation for c in password):
        pool += 32
        breakdown.append("symbols(32)")
    pool = max(pool, 1)
    space = pool ** len(password)
    return pool, space, " + ".join(breakdown)


class BruteForceSimulator:
    def __init__(self):
        self.results = []

    def simulate(self, passwords: list) -> list:
        """
        Simulate brute-force attack on a list of passwords.
        Returns estimated cracking times for each hash algorithm.
        """
        print(f"\n  [*] Simulating brute-force attack on {len(passwords)} password(s)...")
        results = []

        for pwd in passwords:
            pool_size, space, charset_info = _search_space(pwd)
            length = len(pwd)

            # Check if in dictionary
            in_dict = pwd.lower() in COMMON_DICT
            dict_position = COMMON_DICT.index(pwd.lower()) + 1 if in_dict else None

            # --- Incremental brute-force estimate ---
            # Average case = search through half the space
            avg_attempts = space / 2

            time_estimates = {}
            for algo, speed in CRACKING_SPEEDS.items():
                secs = avg_attempts / speed
                time_estimates[algo] = {
                    "seconds": secs,
                    "human": _human_time(secs)
                }

            result = {
                "password": pwd,
                "masked": "*" * len(pwd),   # mask for display
                "length": length,
                "charset_pool": pool_size,
                "charset_info": charset_info,
                "search_space": space,
                "search_space_str": f"{space:,.0f}" if space < 1e18 else f"10^{math.log10(space):.1f}",
                "in_dictionary": in_dict,
                "dict_position": dict_position,
                "time_estimates": time_estimates,
                "risk_level": self._risk_level(pwd, in_dict, space),
            }
            results.append(result)

        self.results = results
        return results

    def _risk_level(self, password: str, in_dict: bool, space: float) -> str:
        if in_dict or space < 1e6:
            return "CRITICAL"
        if space < 1e10:
            return "HIGH"
        if space < 1e14:
            return "MEDIUM"
        if space < 1e18:
            return "LOW"
        return "VERY LOW"

    def show_results(self, results: list):
        """Pretty-print simulation results."""
        RISK_COLOR = {
            "CRITICAL": "!!!",
            "HIGH":     " !!",
            "MEDIUM":   "  !",
            "LOW":      "  ~",
            "VERY LOW": "  ✓",
        }

        for r in results:
            print(f"\n  ┌─ Password: {'*' * r['length']}  (length={r['length']})")
            print(f"  │  Risk Level : {RISK_COLOR.get(r['risk_level'],'')} {r['risk_level']}")
            print(f"  │  Charset    : {r['charset_info']}")
            print(f"  │  Pool Size  : {r['charset_pool']} characters")
            print(f"  │  Search Space: {r['search_space_str']} combinations")

            if r['in_dictionary']:
                print(f"  │  ⚠ FOUND IN DICTIONARY at position #{r['dict_position']}")

            print(f"  │")
            print(f"  │  Estimated Cracking Time (avg-case, GPU):")
            for algo in ["NTLM", "MD5", "SHA256", "SHA512", "bcrypt", "SHA512crypt"]:
                est = r['time_estimates'][algo]
                print(f"  │    {algo:<14}: {est['human']}")
            print(f"  └{'─'*54}")

    def demo_incremental(self, max_length: int = 4, charset: str = "digits"):
        """
        Demo: Show how many combinations exist up to a certain length.
        Helps visualize why short passwords are weak.
        """
        chars = CHARSETS.get(charset, string.digits)
        pool = len(chars)
        print(f"\n  [*] Incremental brute-force demo — charset: {charset} ({pool} chars)")
        print(f"  {'Length':<8} {'Combinations':<22} {'Time (MD5/GPU)'}")
        print("  " + "-" * 50)

        speed = CRACKING_SPEEDS["MD5"]
        total = 0
        for length in range(1, max_length + 1):
            combos = pool ** length
            total += combos
            secs = total / speed
            print(f"  {length:<8} {total:>20,}   {_human_time(secs)}")
