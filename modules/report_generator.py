"""
Module 5: Report Generator
Generates a detailed security audit report from analysis results.
"""

import os
from datetime import datetime


REPORT_HEADER = """
╔══════════════════════════════════════════════════════════════════╗
║          PASSWORD SECURITY AUDIT REPORT                         ║
║          Generated: {timestamp:<40}║
╚══════════════════════════════════════════════════════════════════╝

[DISCLAIMER] This report is generated in a controlled, ethical lab
environment for educational purposes only. All data is simulated.
"""

POLICY_RECOMMENDATIONS = """
RECOMMENDED PASSWORD POLICY
────────────────────────────────────────────────────────
Minimum Length      : 12 characters (16+ for privileged accounts)
Character Classes   : Must include UPPERCASE + lowercase + digits + symbols
Dictionary Check    : Block known common passwords (NIST guidelines)
History             : Prevent reuse of last 10 passwords
Lockout Policy      : Lock after 5 failed attempts / 15 min cooldown
Multi-Factor Auth   : Enforce MFA for all accounts (especially admin)
Storage             : Hash with bcrypt/Argon2 (NEVER MD5 or plain text)
Rotation            : Only require rotation if breach is suspected (NIST 2024)
"""

MITIGATIONS = """
MITIGATION STRATEGIES
────────────────────────────────────────────────────────
1. DEPLOY MULTI-FACTOR AUTHENTICATION (MFA)
   Even if a password is cracked, MFA blocks unauthorized access.

2. USE A MODERN HASHING ALGORITHM
   bcrypt, scrypt, or Argon2 are designed to be slow — making
   brute-force attacks computationally expensive.

3. ENABLE ACCOUNT LOCKOUT POLICIES
   Limit login attempts to prevent online brute-force.

4. INTEGRATE A PASSWORD MANAGER
   Prevents password reuse and enables strong unique passwords.

5. MONITOR FOR CREDENTIAL STUFFING
   Use threat intelligence feeds to detect leaked credentials.

6. CONDUCT REGULAR SECURITY AUDITS
   Periodic reviews catch weak passwords before attackers do.

7. EDUCATE USERS
   Security awareness training on password hygiene is essential.
"""


class ReportGenerator:
    def generate(
        self,
        wordlist_path: str = None,
        bf_results: list = None,
        analysis_results: list = None,
        output_path: str = "output/audit_report.txt"
    ):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = []

        lines.append(REPORT_HEADER.format(timestamp=timestamp))

        # --- Section 1: Wordlist ---
        lines.append("\n" + "─" * 66)
        lines.append("SECTION 1: DICTIONARY / WORDLIST GENERATION")
        lines.append("─" * 66)
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path) as f:
                words = f.readlines()
            lines.append(f"  Wordlist file   : {wordlist_path}")
            lines.append(f"  Total entries   : {len(words):,}")
            lines.append(f"  Sample entries  :")
            for w in words[:10]:
                lines.append(f"    - {w.strip()}")
            lines.append(f"    ... (and {len(words) - 10} more)")
        else:
            lines.append("  No wordlist generated in this run.")

        # --- Section 2: Brute-Force Results ---
        lines.append("\n" + "─" * 66)
        lines.append("SECTION 2: BRUTE-FORCE SIMULATION RESULTS")
        lines.append("─" * 66)
        if bf_results:
            critical = [r for r in bf_results if r["risk_level"] == "CRITICAL"]
            high = [r for r in bf_results if r["risk_level"] == "HIGH"]
            lines.append(f"  Passwords tested     : {len(bf_results)}")
            lines.append(f"  Critical risk        : {len(critical)}")
            lines.append(f"  High risk            : {len(high)}")
            lines.append(f"  Medium/Low/Very Low  : {len(bf_results) - len(critical) - len(high)}")
            lines.append(f"\n  Detailed Results:")
            for r in bf_results:
                lines.append(f"\n  Password (masked): {r['masked']} [{r['length']} chars]")
                lines.append(f"    Risk Level     : {r['risk_level']}")
                lines.append(f"    Search Space   : {r['search_space_str']} combinations")
                lines.append(f"    In Dictionary  : {'YES ⚠' if r['in_dictionary'] else 'No'}")
                lines.append(f"    Crack Time (NTLM/GPU): {r['time_estimates']['NTLM']['human']}")
                lines.append(f"    Crack Time (bcrypt)  : {r['time_estimates']['bcrypt']['human']}")
        else:
            lines.append("  No brute-force simulation data in this run.")

        # --- Section 3: Password Strength Analysis ---
        lines.append("\n" + "─" * 66)
        lines.append("SECTION 3: PASSWORD STRENGTH ANALYSIS")
        lines.append("─" * 66)
        if analysis_results:
            very_weak = [r for r in analysis_results if r["strength"] == "VERY WEAK"]
            weak      = [r for r in analysis_results if r["strength"] == "WEAK"]
            moderate  = [r for r in analysis_results if r["strength"] == "MODERATE"]
            strong    = [r for r in analysis_results if r["strength"] in ("STRONG", "VERY STRONG")]

            lines.append(f"  Passwords analyzed  : {len(analysis_results)}")
            lines.append(f"  Very Weak           : {len(very_weak)}")
            lines.append(f"  Weak                : {len(weak)}")
            lines.append(f"  Moderate            : {len(moderate)}")
            lines.append(f"  Strong / Very Strong: {len(strong)}")

            lines.append(f"\n  Detailed Breakdown:")
            for r in analysis_results:
                lines.append(f"\n  Password (masked): {r['masked']} [{r['length']} chars]")
                lines.append(f"    Strength   : {r['strength']}  (Score: {r['score']}/100)")
                lines.append(f"    Entropy    : {r['entropy_bits']} bits ({r['entropy_rating']})")
                lines.append(f"    Char Types : {r['char_classes']['count']}/4")
                if r["weaknesses"]:
                    lines.append(f"    Weaknesses :")
                    for w in r["weaknesses"]:
                        lines.append(f"      ⚠ {w}")

        else:
            lines.append("  No password analysis data in this run.")

        # --- Section 4: Policy Recommendations ---
        lines.append("\n" + "─" * 66)
        lines.append("SECTION 4: POLICY RECOMMENDATIONS")
        lines.append("─" * 66)
        lines.append(POLICY_RECOMMENDATIONS)

        # --- Section 5: Mitigations ---
        lines.append("\n" + "─" * 66)
        lines.append("SECTION 5: MITIGATION STRATEGIES")
        lines.append("─" * 66)
        lines.append(MITIGATIONS)

        # --- Footer ---
        lines.append("\n" + "═" * 66)
        lines.append(f"  END OF REPORT — {timestamp}")
        lines.append("  This report is for authorized security assessment only.")
        lines.append("═" * 66 + "\n")

        report_text = "\n".join(lines)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        import sys
        if sys.platform == "win32":
            # Replace unicode box-drawing chars for Windows terminal compatibility
            safe_text = report_text
            replacements = {
                "═": "=", "╔": "+", "╗": "+", "╚": "+", "╝": "+",
                "║": "|", "─": "-", "├": "+", "└": "+", "┐": "+",
                "┘": "+", "│": "|", "█": "#", "░": ".", "✓": "OK",
                "⚠": "!!", "→": "->", "•": "*",
            }
            for orig, repl in replacements.items():
                safe_text = safe_text.replace(orig, repl)
            print(safe_text)
        else:
            print(report_text)
        print(f"\n  [OK] Audit report saved to: {output_path}")
        return output_path
