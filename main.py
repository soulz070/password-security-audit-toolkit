"""
Password Cracking & Credential Attack Suite
Main entry point - run all modules from here
"""

import os
import sys
from modules.dictionary_generator import DictionaryGenerator
from modules.hash_extractor import HashExtractor
from modules.brute_force_simulator import BruteForceSimulator
from modules.password_analyzer import PasswordAnalyzer
from modules.report_generator import ReportGenerator

import sys
import os

# Fix Windows terminal encoding for UTF-8 characters
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        os.system("chcp 65001 > nul")  # Set Windows console to UTF-8
    except Exception:
        pass


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║       Password Cracking & Credential Attack Suite            ║
║              [ETHICAL / EDUCATIONAL USE ONLY]                ║
╠══════════════════════════════════════════════════════════════╣
║  Module 1: Dictionary Generator                              ║
║  Module 2: Hash Extractor (Demo)                             ║
║  Module 3: Brute-Force Simulator                             ║
║  Module 4: Password Strength Analyzer                        ║
║  Module 5: Report Generator                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

MENU = """
[1] Generate Dictionary / Wordlist
[2] Hash Extraction Demo
[3] Brute-Force Simulator
[4] Password Strength Analyzer
[5] Generate Audit Report
[6] Run Full Suite (All Modules)
[0] Exit
"""


def run_full_suite():
    print("\n[*] Running full suite...\n")

    # --- Module 1: Dictionary ---
    print("=" * 60)
    print("[MODULE 1] Dictionary Generator")
    print("=" * 60)
    dg = DictionaryGenerator()
    dg.generate_from_pattern("john", "1990")
    dg.apply_mutations(["password", "admin", "john1990"])
    dg.save_wordlist("output/wordlist.txt")

    # --- Module 2: Hash Extraction ---
    print("\n" + "=" * 60)
    print("[MODULE 2] Hash Extractor")
    print("=" * 60)
    he = HashExtractor()
    he.demo_linux_shadow()
    he.demo_windows_sam()

    # --- Module 3: Brute Force ---
    print("\n" + "=" * 60)
    print("[MODULE 3] Brute-Force Simulator")
    print("=" * 60)
    bf = BruteForceSimulator()
    results = bf.simulate(["abc123", "P@ssw0rd", "hello", "X9#kLm2!"])
    bf.show_results(results)

    # --- Module 4: Analyzer ---
    print("\n" + "=" * 60)
    print("[MODULE 4] Password Strength Analyzer")
    print("=" * 60)
    pa = PasswordAnalyzer()
    test_passwords = ["password", "P@ssw0rd!", "abc123", "Tr0ub4dor&3", "qwerty", "MyDog$Fluffy99"]
    analysis_results = []
    for pwd in test_passwords:
        result = pa.analyze(pwd)
        pa.print_result(result)
        analysis_results.append(result)

    # --- Module 5: Report ---
    print("\n" + "=" * 60)
    print("[MODULE 5] Report Generator")
    print("=" * 60)
    rg = ReportGenerator()
    rg.generate(
        wordlist_path="output/wordlist.txt",
        bf_results=results,
        analysis_results=analysis_results,
        output_path="output/audit_report.txt"
    )

    print("\n[✓] Full suite completed. Check output/ folder for results.")


def main():
    print(BANNER)
    os.makedirs("output", exist_ok=True)
    os.makedirs("wordlists", exist_ok=True)

    while True:
        print(MENU)
        choice = input("Select module [0-6]: ").strip()

        if choice == "1":
            dg = DictionaryGenerator()
            name = input("  Enter base name (e.g. john): ").strip() or "john"
            dob = input("  Enter year of birth (e.g. 1990): ").strip() or "1990"
            dg.generate_from_pattern(name, dob)
            base_words = input("  Extra base words (comma-separated, blank to skip): ").strip()
            if base_words:
                dg.apply_mutations(base_words.split(","))
            dg.save_wordlist("output/wordlist.txt")

        elif choice == "2":
            he = HashExtractor()
            he.demo_linux_shadow()
            he.demo_windows_sam()

        elif choice == "3":
            bf = BruteForceSimulator()
            passwords = input("  Enter passwords to simulate (comma-separated): ").strip()
            pwd_list = [p.strip() for p in passwords.split(",")] if passwords else ["abc123", "hello"]
            results = bf.simulate(pwd_list)
            bf.show_results(results)

        elif choice == "4":
            pa = PasswordAnalyzer()
            pwd = input("  Enter password to analyze: ").strip()
            if pwd:
                result = pa.analyze(pwd)
                pa.print_result(result)

        elif choice == "5":
            rg = ReportGenerator()
            rg.generate(output_path="output/audit_report.txt")

        elif choice == "6":
            run_full_suite()

        elif choice == "0":
            print("\n[*] Exiting. Stay ethical!\n")
            sys.exit(0)

        else:
            print("  [!] Invalid choice. Try again.")


if __name__ == "__main__":
    main()
