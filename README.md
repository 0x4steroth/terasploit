
# Terasploit Framework

**An opensource python exploitation framework for security researchers and red team operators.**

---

## Overview

**Terasploit Framework (TSF)** is a structured exploitation framework built entirely in Python, designed for security researchers, penetration testers, and red team operators.

Inspired by the architecture and workflow of Metasploit, TSF explores a Python-first approach - leveraging the language most dominant across modern cybersecurity tooling. Where existing frameworks are often tied to Ruby, TSF prioritises Python's ecosystem, accessibility, and integration potential.

The long-term goal is a powerful, community-driven framework that pairs Metasploit's proven workflow model with Python's flexibility.

---

## Requirements

**Python 3.13 or later** is required.

```bash
pip install -r data/requirements/reqs-extra.txt
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/0x4steroth/terasploit.git
cd terasploit

# Install extras
pip install -r data/requirements/reqs-extra.txt

# Make entry points executable
chmod +x teraconsole terax terasm

# No package installation step is required. The framework adds its own root to `sys.path` at startup.
./teraconsole
```

### System Installation

```bash
# Clone the repository
git clone https://github.com/0x4steroth/terasploit.git
cd terasploit

# Install via pip - be careful with '--break-system-packages'
python3 -m pip install -e . --break-system-packages

# Execute
teraconsole

```

---

## Contributing

Contributions are welcome. Please open an issue before starting work on significant changes. All modules should pass `ruff check` and `pyright` before submission.

---

## Disclaimer

Terasploit is intended exclusively for **authorized security testing and educational research**. Use against systems you do not own or lack explicit written permission to test is illegal and unethical. The authors accept no liability for misuse.

---

<div align="center">
<sub>Built with Python · BSD-3-Clause · <a href="https://github.com/0x4steroth/terasploit">github.com/0x4steroth/terasploit</a></sub>
</div>
