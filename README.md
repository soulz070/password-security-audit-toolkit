# Password Security Audit Toolkit

⚠ **Ethical / educational use only.** A modular Python toolkit for password-policy testing and credential security assessment, built for use in controlled lab environments.

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | `dictionary_generator.py` | Generates custom wordlists using name/DOB patterns, leet-speak, keyboard walks, case variations and mutation rules |
| 2 | `hash_extractor.py` | Demonstrates Linux `/etc/shadow` and Windows SAM hash formats using sample data, plus a multi-algorithm hash-generation utility (MD5/SHA1/SHA256/SHA512/NTLM) |
| 3 | `brute_force_simulator.py` | Estimates time-to-crack per password across six hashing algorithms using real-world GPU benchmark speeds |
| 4 | `password_analyzer.py` | Entropy-based strength scoring (0–100) with character-class and weakness detection (dictionary words, keyboard walks, repetition, sequential numbers) |
| 5 | `report_generator.py` | Aggregates all module output into a structured security-audit report |

## Requirements

Python 3.8+ — standard library only, no external dependencies.

## Usage

Interactive menu:

```bash
python3 main.py
```

Or run the full suite (all 5 modules) directly from the menu's option 6. Output files are written to `output/`:
- `output/wordlist.txt` — generated wordlist
- `output/audit_report.txt` — full security audit report

## Project structure

```
password_toolkit/
├── main.py                       # Entry point with interactive menu
├── modules/
│   ├── dictionary_generator.py   # Module 1
│   ├── hash_extractor.py         # Module 2
│   ├── brute_force_simulator.py  # Module 3
│   ├── password_analyzer.py      # Module 4
│   └── report_generator.py       # Module 5
└── output/                       # Generated wordlist + report (gitignored)
```

## Documentation

Full project documentation — architecture, module-by-module breakdown, scoring design, and sample output — is in [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) (also available as the original Word doc, [`docs/Project_Documentation.docx`](docs/Project_Documentation.docx)).

## Disclaimer

This toolkit uses only sample/demo data for hash extraction and does **not** interact with real system files or credentials. It is intended strictly for authorized, ethical security-assessment and educational use in environments you own or are explicitly authorized to test.
