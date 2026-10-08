"""
Module 4: Password Strength Analyzer
Evaluates password complexity, entropy, and predictability.
"""

import re
import math
import string


# Common dictionary words to check against
DICTIONARY_WORDS = [
    "password", "admin", "login", "user", "welcome", "abc",
    "qwerty", "hello", "monkey", "dragon", "master", "shadow",
    "letmein", "test", "guest", "root", "iloveyou", "sunshine",
    "princess", "football", "baseball", "superman", "batman",
    "donald", "michael", "jennifer", "password1", "pass",
]

# Common keyboard patterns
KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "zxcvbn",
    "1234567890", "123456", "12345678", "1qaz2wsx",
    "qazwsx", "!@#$%^", "0987654321",
]

# Scoring weights
SCORE_MAX = 100


class PasswordAnalyzer:
    def __init__(self):
        pass

    def analyze(self, password: str) -> dict:
        """Full password analysis — returns structured result."""
        result = {
            "password": password,
            "masked": self._mask(password),
            "length": len(password),
        }

        # --- Character class checks ---
        has_lower   = bool(re.search(r"[a-z]", password))
        has_upper   = bool(re.search(r"[A-Z]", password))
        has_digit   = bool(re.search(r"\d", password))
        has_symbol  = bool(re.search(r"[^a-zA-Z0-9]", password))
        char_classes = sum([has_lower, has_upper, has_digit, has_symbol])

        result["char_classes"] = {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits":    has_digit,
            "symbols":   has_symbol,
            "count":     char_classes,
        }

        # --- Entropy calculation ---
        pool = 0
        if has_lower:   pool += 26
        if has_upper:   pool += 26
        if has_digit:   pool += 10
        if has_symbol:  pool += 32
        pool = max(pool, 1)
        entropy = len(password) * math.log2(pool)
        result["entropy_bits"] = round(entropy, 2)
        result["entropy_rating"] = self._entropy_rating(entropy)

        # --- Weakness checks ---
        weaknesses = []

        if len(password) < 8:
            weaknesses.append("TOO SHORT — minimum 8 characters recommended")
        if len(password) < 12:
            weaknesses.append("SHORT — 12+ characters strongly recommended")
        if not has_upper:
            weaknesses.append("No uppercase letters")
        if not has_lower:
            weaknesses.append("No lowercase letters")
        if not has_digit:
            weaknesses.append("No digits")
        if not has_symbol:
            weaknesses.append("No special symbols")

        # Dictionary word check
        pwd_lower = password.lower()
        for word in DICTIONARY_WORDS:
            if word in pwd_lower:
                weaknesses.append(f"Contains dictionary word: '{word}'")
                break

        # Keyboard walk check
        for walk in KEYBOARD_WALKS:
            if walk in pwd_lower:
                weaknesses.append(f"Contains keyboard pattern: '{walk}'")
                break

        # Repeated characters check
        if re.search(r"(.)\1{2,}", password):
            weaknesses.append("Contains 3+ repeated consecutive characters (e.g. 'aaa')")

        # Sequential numbers
        if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
            weaknesses.append("Contains sequential numbers (e.g. '123')")

        # All same character class
        if char_classes == 1:
            weaknesses.append("Uses only ONE character class — very weak")

        result["weaknesses"] = weaknesses

        # --- Scoring ---
        score = self._compute_score(password, entropy, char_classes, weaknesses)
        result["score"] = score
        result["strength"] = self._strength_label(score)
        result["strength_bar"] = self._strength_bar(score)

        # --- Recommendations ---
        result["recommendations"] = self._recommendations(result)

        return result

    def _mask(self, password: str) -> str:
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def _entropy_rating(self, bits: float) -> str:
        if bits < 28:   return "Very Weak"
        if bits < 36:   return "Weak"
        if bits < 60:   return "Moderate"
        if bits < 80:   return "Strong"
        return "Very Strong"

    def _compute_score(self, password, entropy, char_classes, weaknesses) -> int:
        score = 0

        # Length scoring (up to 30 pts)
        length = len(password)
        if length >= 20: score += 30
        elif length >= 16: score += 25
        elif length >= 12: score += 20
        elif length >= 10: score += 15
        elif length >= 8:  score += 10
        else:              score += 0

        # Char class scoring (up to 30 pts)
        score += char_classes * 7

        # Entropy scoring (up to 30 pts)
        if entropy >= 80:   score += 30
        elif entropy >= 60: score += 25
        elif entropy >= 40: score += 20
        elif entropy >= 28: score += 10
        else:               score += 0

        # Penalty per weakness
        score -= len(weaknesses) * 5

        return max(0, min(100, score))

    def _strength_label(self, score: int) -> str:
        if score >= 80: return "VERY STRONG"
        if score >= 60: return "STRONG"
        if score >= 40: return "MODERATE"
        if score >= 20: return "WEAK"
        return "VERY WEAK"

    def _strength_bar(self, score: int) -> str:
        filled = score // 5
        empty = 20 - filled
        return "[" + "█" * filled + "░" * empty + f"] {score}/100"

    def _recommendations(self, result: dict) -> list:
        recs = []
        if result["length"] < 12:
            recs.append("Use at least 12–16 characters")
        if not result["char_classes"]["uppercase"]:
            recs.append("Add uppercase letters (A–Z)")
        if not result["char_classes"]["digits"]:
            recs.append("Add digits (0–9)")
        if not result["char_classes"]["symbols"]:
            recs.append("Add special characters (!@#$%^&*)")
        if result["weaknesses"]:
            recs.append("Avoid dictionary words, keyboard patterns, and repeated characters")
        if result["score"] < 60:
            recs.append("Consider using a passphrase: 4+ random words (e.g. correct-horse-battery-staple)")
        recs.append("Use a password manager to generate and store strong unique passwords")
        return recs

    def print_result(self, result: dict):
        """Pretty-print analysis result for a password."""
        print(f"\n  ┌─ Password: {result['masked']}  (length={result['length']})")
        print(f"  │  Strength   : {result['strength']}")
        print(f"  │  Score      : {result['strength_bar']}")
        print(f"  │  Entropy    : {result['entropy_bits']} bits  ({result['entropy_rating']})")

        cc = result["char_classes"]
        classes_str = []
        if cc["lowercase"]: classes_str.append("lowercase")
        if cc["uppercase"]: classes_str.append("UPPERCASE")
        if cc["digits"]:    classes_str.append("digits")
        if cc["symbols"]:   classes_str.append("symbols")
        print(f"  │  Char Types : {', '.join(classes_str) if classes_str else 'none'} ({cc['count']}/4)")

        if result["weaknesses"]:
            print(f"  │  Weaknesses :")
            for w in result["weaknesses"]:
                print(f"  │    ⚠ {w}")
        else:
            print(f"  │  Weaknesses : None detected ✓")

        print(f"  │  Suggestions:")
        for rec in result["recommendations"]:
            print(f"  │    → {rec}")

        print(f"  └{'─'*54}")

    def batch_analyze(self, passwords: list) -> list:
        """Analyze multiple passwords and return sorted by score."""
        results = [self.analyze(p) for p in passwords]
        return sorted(results, key=lambda x: x["score"])
