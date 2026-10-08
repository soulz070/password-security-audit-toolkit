"""
Module 1: Dictionary Generator
Generates custom wordlists with pattern-based and mutation-based techniques.
"""

import os
import itertools
from datetime import datetime


# Common password bases used in attacks
COMMON_PASSWORDS = [
    "password", "admin", "123456", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "master", "login",
    "pass", "test", "user", "guest", "root", "abc123",
    "iloveyou", "sunshine", "princess", "football"
]

# Keyboard walk patterns
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "1qaz2wsx", "qazwsx", "1234qwer",
    "!@#$%^", "qweasdzxc"
]

# Leet-speak substitution map
LEET_MAP = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0',
    's': '$', 't': '7', 'l': '1', 'b': '8'
}


class DictionaryGenerator:
    def __init__(self):
        self.wordlist = set()
        self.stats = {}

    def generate_from_pattern(self, name: str, year: str):
        """Generate words based on name + date of birth patterns."""
        print(f"\n  [*] Generating pattern-based wordlist for '{name}' ({year})...")

        name_lower = name.lower()
        name_cap = name.capitalize()
        short_year = year[-2:]  # e.g. 90 from 1990

        patterns = [
            name_lower,
            name_cap,
            name_lower + year,
            name_lower + short_year,
            name_cap + year,
            name_cap + short_year,
            name_lower + "123",
            name_lower + "!",
            name_lower + "1",
            name_cap + "!",
            year + name_lower,
            name_lower + "@" + year,
            name_lower + "#" + year,
            name_lower.upper(),
            name_lower.upper() + year,
            name_lower[::-1],          # reversed
            name_lower + "password",
            "password" + year,
            name_lower + "pass",
        ]

        # Add common password combos
        for common in COMMON_PASSWORDS:
            patterns.append(common)
            patterns.append(common + short_year)
            patterns.append(common + year)

        # Add keyboard patterns
        patterns.extend(KEYBOARD_PATTERNS)

        for p in patterns:
            self.wordlist.add(p)

        self.stats['pattern_count'] = len(patterns)
        print(f"  [✓] Generated {len(patterns)} pattern-based entries")

    def apply_mutations(self, base_words: list):
        """Apply leet-speak, case variations, and number appending mutations."""
        print(f"\n  [*] Applying mutations to {len(base_words)} base word(s)...")
        original_count = len(self.wordlist)

        for word in base_words:
            word = word.strip()
            if not word:
                continue

            # Case variations
            self.wordlist.add(word.lower())
            self.wordlist.add(word.upper())
            self.wordlist.add(word.capitalize())
            self.wordlist.add(word.title())

            # Number appending
            for n in range(10):
                self.wordlist.add(word + str(n))
                self.wordlist.add(word.capitalize() + str(n))
            for n in ["123", "1234", "12345", "!", "!!", "!@#", "2024", "2023", "2022"]:
                self.wordlist.add(word + n)
                self.wordlist.add(word.capitalize() + n)

            # Leet-speak substitutions
            leet_word = ""
            for char in word.lower():
                leet_word += LEET_MAP.get(char, char)
            if leet_word != word.lower():
                self.wordlist.add(leet_word)
                self.wordlist.add(leet_word.capitalize())
                self.wordlist.add(leet_word + "!")
                self.wordlist.add(leet_word + "123")

            # Reversed word
            self.wordlist.add(word[::-1])

            # Double word
            self.wordlist.add(word + word)

            # Word with year suffix patterns
            for yr in ["2023", "2024", "2025"]:
                self.wordlist.add(word + yr)

        added = len(self.wordlist) - original_count
        self.stats['mutation_count'] = added
        print(f"  [✓] Mutation applied — {added} new entries added (Total: {len(self.wordlist)})")

    def save_wordlist(self, filepath: str):
        """Save the generated wordlist to a file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        sorted_words = sorted(self.wordlist)
        with open(filepath, "w") as f:
            for word in sorted_words:
                f.write(word + "\n")
        print(f"\n  [✓] Wordlist saved to '{filepath}' ({len(sorted_words)} entries)")
        return sorted_words

    def show_sample(self, n=15):
        """Display a sample of the generated wordlist."""
        sample = list(self.wordlist)[:n]
        print(f"\n  Sample entries ({n} of {len(self.wordlist)}):")
        for i, word in enumerate(sample, 1):
            print(f"    {i:>3}. {word}")
