# Password Cracking & Credential Attack Suite — Project Documentation

*Project Documentation & Technical Report*

> ⚠ **Ethical & educational use only.**
> The original formatted Word document is also available in this folder: [`Project_Documentation.docx`](./Project_Documentation.docx)

| | |
|---|---|
| **Subject** | Cybersecurity — Password Security Assessment |
| **Level** | Intermediate |
| **Language** | Python 3.x |
| **Modules** | 5 (Dictionary, Hash, Brute-Force, Analyzer, Report) |

## 1. Project Overview

This project implements a Password Cracking & Credential Attack Suite — a practical, modular toolkit for password policy testing and credential security assessment. The toolkit is built entirely in Python and is designed for use in ethical, controlled lab environments only.

Weak passwords remain among the most exploited vulnerabilities in modern cybersecurity. Attackers routinely use dictionary attacks, credential dumping, and brute-force techniques to compromise accounts and escalate privileges. This project provides hands-on experience with these techniques from both the attacker (red team) and defender (blue team) perspectives.

### 1.1 Practical Motivation

Poor password practices lead to:

- Account takeovers and unauthorized access
- Privilege escalation attacks
- Large-scale data breaches
- Credential stuffing campaigns using leaked databases

### 1.2 What This Toolkit Does

| # | Module | Description | Status |
|---|---|---|---|
| 1 | Dictionary Generator | Generates custom wordlists using pattern-based and mutation techniques | Complete |
| 2 | Hash Extractor | Demonstrates Linux `/etc/shadow` and Windows SAM hash extraction (demo data) | Complete |
| 3 | Brute-Force Simulator | Simulates cracking attempts and estimates time-to-crack per algorithm | Complete |
| 4 | Password Analyzer | Evaluates entropy, complexity, weaknesses, and provides recommendations | Complete |
| 5 | Report Generator | Produces a full security audit report from all module outputs | Complete |

## 2. System Architecture & Workflow

The toolkit follows a modular, pipeline-based architecture. Each module can be run independently or as part of the full suite via `main.py`.

### 2.1 Project Structure

```
password_toolkit/
├── main.py                       # Entry point with interactive menu
├── modules/
│   ├── dictionary_generator.py   # Module 1
│   ├── hash_extractor.py         # Module 2
│   ├── brute_force_simulator.py  # Module 3
│   ├── password_analyzer.py      # Module 4
│   └── report_generator.py       # Module 5
└── output/
    ├── wordlist.txt               # Generated wordlist
    └── audit_report.txt           # Final audit report
```

### 2.2 Workflow

```
User Input → Dictionary Generation → Hash Extraction (Demo)
    ↓
Brute-Force Simulation → Strength Analysis → Audit Report
```

## 3. Module Documentation

### Module 1 — Dictionary Generator

*File: `modules/dictionary_generator.py`*

Builds custom wordlists targeting specific users or organizations, combining pattern-based generation with mutation rules.

**Key functions**
- `generate_from_pattern(name, year)` — creates words from name+DOB combinations, keyboard walks, and common passwords
- `apply_mutations(base_words)` — applies leet-speak substitutions, case variations, number appending, and reversal
- `save_wordlist(filepath)` — saves the deduplicated wordlist to a `.txt` file

**Techniques implemented**
- Name + date-of-birth patterns (`john1990`, `John1990!`, `john@1990`)
- Leet-speak substitution (a→@, e→3, i→1, o→0, s→$, t→7)
- Case variations: lower, UPPER, Capitalized, Title
- Keyboard walk patterns (`qwerty`, `1qaz2wsx`, `asdfgh`)
- Number and symbol appending (`password123`, `password!`, `password2024`)

### Module 2 — Hash Extractor

*File: `modules/hash_extractor.py`*

Demonstrates how password hashes are stored in Linux and Windows systems, using sample/demo data only — never touches real system files.

**Linux `/etc/shadow` format**

```
username:$id$salt$hash:last_change:min:max:warn:inactive:expire
```

| Prefix | Algorithm | Notes |
|---|---|---|
| `$1$` | MD5 | Obsolete — easily cracked |
| `$5$` | SHA-256 | Moderate security |
| `$6$` | SHA-512 | Default on modern Linux |
| `$2b$` | bcrypt | Strongest — slow by design |

**Windows SAM format**

The SAM database stores NTLM (NT) hashes. An empty LM hash is `aad3b435b51404eeaad3b435b51404ee`; a blank-password NT hash is `31d6cfe0d16ae931b73c59d7e0c089c0` — both immediately recognizable to defenders.

### Module 3 — Brute-Force Simulator

*File: `modules/brute_force_simulator.py`*

Computes the theoretical search space for any password and estimates time-to-crack across six hashing algorithms using real-world GPU benchmark speeds.

**Cracking speed reference (GPU benchmarks)**

| Algorithm | Speed (hashes/sec) | Security Level |
|---|---|---|
| NTLM / MD5 | 10 billion/sec | Very Weak (never use) |
| SHA-256 | 1 billion/sec | Weak for passwords |
| SHA-512 | 500 million/sec | Weak for passwords |
| bcrypt | 15,000/sec | Strong (use this!) |
| SHA-512crypt (`$6$`) | 20,000/sec | Strong |

**Risk level classification**
- **CRITICAL** — in dictionary OR search space < 10⁶ (cracked instantly)
- **HIGH** — search space 10⁶–10¹⁰ (seconds to minutes)
- **MEDIUM** — search space 10¹⁰–10¹⁴ (minutes to hours)
- **LOW** — search space 10¹⁴–10¹⁸ (hours to months)
- **VERY LOW** — search space > 10¹⁸ (years, practically uncrackable)

### Module 4 — Password Strength Analyzer

*File: `modules/password_analyzer.py`*

Provides a comprehensive strength analysis using entropy calculation, character-class detection, dictionary/pattern checking, and a composite 100-point scoring system.

**Entropy calculation:** `bits = length × log₂(pool_size)`, where pool_size is the number of unique character types used (lowercase=26, +uppercase=52, +digits=62, +symbols=94).

**Scoring system (0–100)**
- Length score: up to 30 points (20pts for 12+ chars, 30pts for 20+ chars)
- Character class score: up to 28 points (7pts per class: lower, UPPER, digit, symbol)
- Entropy score: up to 30 points (30pts for 80+ bits)
- Weakness penalty: −5 points per weakness detected

**Weakness detectors**
- Dictionary word presence (common words checked)
- Keyboard walk patterns (`qwerty`, `asdfgh`, `1234`, etc.)
- Repeated characters (`aaa`, `111`, etc.)
- Sequential numbers (`123`, `456`, `789`)
- Single character class usage
- Length below 8 or 12 characters

### Module 5 — Report Generator

*File: `modules/report_generator.py`*

Aggregates outputs from all previous modules into a structured security audit report saved as a text file, covering:

1. Wordlist summary and sample entries
2. Brute-force simulation results with risk levels and crack times
3. Detailed password strength analysis for each tested password
4. Recommended password policy (NIST-aligned)
5. Mitigation strategies (MFA, hashing, lockout, auditing)

## 4. Running the Toolkit

### 4.1 Prerequisites

- Python 3.8 or higher
- No external pip packages required — standard library only
- Tested on Linux and Windows

### 4.2 How to Run

**Option A — Interactive menu**

```bash
cd password_toolkit
python3 main.py
```

The interactive menu lets you run each module individually or all together (option 6).

### 4.3 Output Files

- `output/wordlist.txt` — generated password wordlist
- `output/audit_report.txt` — full security audit report

## 5. Sample Output

**Dictionary Generator**

```
[*] Generating pattern-based wordlist for 'alice' (1995)...
[✓] Generated 89 pattern-based entries
[*] Applying mutations to 3 base word(s)...
[✓] Mutation applied — 137 new entries added (Total: 224)
[✓] Wordlist saved to 'output/wordlist.txt' (224 entries)
```

**Brute-Force Simulation**

```
Password: abc123 (length=6)  | CRITICAL RISK
  Search Space : 2,176,782,336 combinations
  In Dictionary: YES ⚠
  NTLM (GPU)   : < 1 second
  bcrypt       : 20.2 hours

Password: *********** (length=11) | VERY LOW RISK
  Search Space : 10^21.7 combinations
```

---

*Password Cracking & Credential Attack Suite — Project Documentation*
