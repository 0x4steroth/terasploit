# Terasploit Module Development Guide

This guide covers important things to write, structure, and test modules for
the Terasploit Framework (TSF). It assumes familiarity with Python and basic
familiarity with the TSF console (`teraconsole`).

---

## Table of Contents

- [Module System Overview](#module-system-overview)
- [Directory Layout](#directory-layout)
- [Module Discovery](#module-discovery)
- [Common Attributes](#common-attributes)
- [Option System](#option-system)
- [Module Types](#module-types)
  - [Exploit](#exploit)
  - [Auxiliary](#auxiliary)
  - [Post](#post)
  - [Encoder](#encoder)
  - [Nops](#nops)
  - [Evasion](#evasion)
- [Context Objects](#context-objects)
- [Ranks](#ranks)
- [Platform and Architecture Constants](#platform-and-architecture-constants)
- [Naming Conventions](#naming-conventions)
- [Checklist](#checklist)

---

## Module System Overview

Every module is a Python file containing a single class named
`TerasploitModule` that inherits from the appropriate base class. The framework
discovers modules by walking the `modules/` directory tree at startup — no
registration step is needed. Drop a correctly structured file in the right
subdirectory and it will appear in `show <category>` immediately after
`reload`.

All module types share the same basic shapes:

```
modules/<category>/<topic>/<name>.py
modules/<category>/<platform>/<topic>/<name>.py
modules/<category>/<platform>/<architecture>/<topic>/<name>.py
```

The dotted module name used in `use` is derived from the path by replacing
directory separators with dots and dropping the `.py` extension:

```
modules/exploit/multi/handler.py  →  exploit.multi.handler
use exploit/multi/handler
```

---

## Directory Layout

```
modules/
  auxiliary/        Auxiliary modules (scanners, fuzzers, tools)
  encoder/          Encoder modules
  evasion/          Evasion modules
  exploit/          Exploit modules
  nop/              NOP sled modules
  payload/          Payload modules (stagers, stages, singles, adapters)
  post/             Post-exploitation modules
```

Pick the category directory that matches your module type, then organise
further by using the basic shapes we mentioned in the module system overview.

---

## Module Discovery

`ModuleIndex` (@ `teralibs/tsf/utils/path.py`) scans `modules/` recursively for
`*.py` files, excluding `__init__.py`. It builds a map of dotted names to
file paths and caches it. The cache is invalidated by `reload`.

Rules:

- The class inside the module **must** be named `TerasploitModule`.
- if you must use `__init__()`, always put `*args` and `**kwargs` as argument then `super().__init__(*args, **kwargs)`.
```python
class TerasploitModule:
    """A terasploit module."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
```

---

## Common Attributes

Every module type declares the following class-level attributes. All are
strings unless noted otherwise. For unfamiliar attributes, you may check the MRO and module imports to know who uses that attribute.

| Attribute | Type | Required | Description |
|---|---|---|---|
| `NAME` | `str` | Yes | Human-readable name shown in listings and `info` |
| `DESCRIPTION` | `str` | Yes | One-paragraph description of what the module does |
| `AUTHOR` | `str` | Yes | Author handle or contact |
| `LICENSE` | `str` | Yes | SPDX identifier, e.g. `"BSD-3-CLAUSE"` |
| `VERSION` | `str` | Yes | Semantic version string, e.g. `"1.0"` |
| `RANK` | `str` | Yes | Reliability ranking — see [Ranks](#ranks) |
| `REFERENCES` | `list` | No | External references as `[type, url]` pairs |
| `ARCH` | `list[str]` | Yes | Target architectures — see [constants](#platform-and-architecture-constants) |
| `PLATFORM` | `list[str]` | Yes | Target platforms — see [constants](#platform-and-architecture-constants) |
| `OPTIONS` | `list[str]` | No | Keys of options shown by `show options` |
| `ADVANCED_OPTIONS` | `list[str]` | No | Keys of options shown by `show advanced` |
| `EVASION_OPTIONS` | `list[str]` | No | Keys of options shown by `show evasion` |

Use `["all"]` for `ARCH` or `PLATFORM` when the module is not
architecture/platform-specific. We don't need multi for this because we can just add all the compatible platforms and architectures in the list. However, we will use multi as a part of the module path so we know that the module supports multiple platform/architecture.

---

## Option System

Options are key-value pairs stored in the framework's global `DATASTORE`. Each
key must exist in the `OPTION_REGISTRY` (defined in
`teralibs/terasploit/framework/options/storage.py`) or be registered by the module
itself at instantiation time.

### Declaring options from the registry

Reference existing option keys in `OPTIONS`:

```python
OPTIONS = ["RHOST", "RPORT"]
```

Any key listed in `OPTIONS` will appear under `show options` and will be
enforced by `missing_required` when the user runs the module.

### Registering custom options

Call `self.register_options()` inside `__init__` to add options not present
in the registry:

```python
from teralibs.terasploit.framework.options.validators import OptionType

def __init__(self):
    super().__init__()
    self.register_options([
        self.opt(
            name="TIMEOUT",
            default="5",
            required=False,
            desc="Connection timeout in seconds",
            opt_type=OptionType.INTEGER,
        ),
        self.opt(
            name="USERNAME",
            default="admin",
            required=True,
            desc="Target username",
            opt_type=OptionType.STRING,
        ),
    ])
```

`self.opt` is a shorthand for the `Option` dataclass (@ `Base.__init__`).
`self.opt_type` is a shorthand for the OptionType dataclass.

### Option Type Values

| Value | Description |
|---|---|
| `self.opt_type.STRING` | Arbitrary string |
| `self.opt_type.INTEGER` | Integer value |
| `self.opt_type.FLOAT` | Floating-point value |
| `self.opt_type.BOOL` | Boolean |
| `self.opt_type.PORT` | TCP/UDP port number (1–65535) |
| `self.opt_type.ADDRESS` | IP address or hostname |
| `self.opt_type.PATH` | Filesystem path |

### Reading option values at runtime

How options are read depends on the module type — each type receives a
different context object. See [Context Objects](#context-objects) for the
full breakdown.

---

## Module Types

### Exploit

Exploit modules deliver a payload to a target and open a session. They are
driven by `ExploitDriver`, which handles TCP connections, payload assembly,
encoding, and NOP sled prepending automatically.

**Base class:** `teralibs.tsf.base.exploit.Exploit`

**File location:** `modules/exploit/...`

**Skeleton:**

```python
from teralibs.tsf.base.exploit import (
    ARCH_X64, ARCH_X86,
    PLATFORM_LINUX, PLATFORM_WINDOWS,
    Exploit,
)

class TerasploitModule(Exploit):
    NAME        = "My Exploit"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"
    VERSION     = "1.0"
    RANK        = "normal"
    REFERENCES  = [["URL", "https://example.com/advisory"]]

    ARCH        = [ARCH_X86, ARCH_X64]
    PLATFORM    = [PLATFORM_WINDOWS]

    # Buffer size the delivery mechanism can carry.
    # Set None to skip the size check entirely.
    PAYLOAD_SPACE = 4096

    # Targets as (index, label) pairs.
    TARGET = [
        (0, "Windows x86 Automatic"),
        (1, "Windows x64 Automatic"),
    ]

    OPTIONS          = ["RHOST", "RPORT"]
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS  = []

    def run(self, ctx):
        ...

    def check(self, ctx):
        ...

    def stop(self):
        ...
```
`PAYLOAD_SPACE = None` skips the size check. Set it explicitly when the delivery buffer has a known limit.
`TARGET` is required for the `set TARGET` command to work. Index `0` is setautomatically on load.
`check()` and `stop()` are optional. Omit them if not needed.

---

### Auxiliary

Auxiliary modules perform supporting tasks — scanning, fuzzing, brute-forcing,
information gathering — without delivering a payload or opening a session.

**Base class:** `teralibs.tsf.base.auxiliary.Auxiliary`

**File location:** `modules/auxiliary/...`

**Skeleton:**

```python
from teralibs.tsf.base.auxiliary import (
    ARCH_X64, ARCH_X86,
    PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS,
    Auxiliary,
)

class TerasploitModule(Auxiliary):
    NAME        = "My Scanner"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"
    VERSION     = "1.0"
    RANK        = "normal"
    REFERENCES  = []

    ARCH        = [ARCH_X86, ARCH_X64]
    PLATFORM    = [PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS]

    OPTIONS          = ["RHOST", "RPORT"]
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS  = []

    def run(self, ctx):
        ...

    def check(self, ctx):
        ...

```
No payload assembly, no session, no TCP driver — keep it simple.

---

### Post

Post-exploitation modules run against an already-open session to gather
information, escalate privileges, or pivot further.

**Base class:** `teralibs.tsf.base.post.Post`

**File location:** `modules/post/...`

**Skeleton:**

```python
from teralibs.tsf.base.post import (
    ARCH_CMD,
    PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS,
    Post,
)

class TerasploitModule(Post):
    NAME        = "My Post Module"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"
    VERSION     = "1.0"
    RANK        = "normal"
    REFERENCES  = []

    ARCH            = ["all"]
    PLATFORM        = [PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS]
    SESSION_TYPES   = ["shell"]   # ["shell"] or [] for any

    OPTIONS          = []
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS  = []

    def run(self, ctx):
        ...
```
Set `SESSION` with `set SESSION <id>` before running.
`SESSION_TYPES` is advisory metadata. An empty list means any session type is accepted.

---

### Encoder

Encoder modules transform payload bytes to avoid bad characters or evade
signature detection. They expose an `encode_block()` method and are invoked
automatically by `EncoderFactory` during payload assembly.

**Base class:** `teralibs.tsf.base.encoder.Encoder`

**File location:** `modules/encoder/...`

**Skeleton:**

```python
from teralibs.tsf.base.encoder import Encoder, EncoderRank, EncoderState

class TerasploitModule(Encoder):
    NAME        = "My Encoder"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"
    VERSION     = "1.0"
    RANK        = EncoderRank.NORMAL

    ARCH        = ["x86"]
    PLATFORM    = ["all"]

    OPTIONS          = []
    ADVANCED_OPTIONS = []

    def encode(
        self, raw_bytes: bytes, bad_bytes: frozenset[int], ctx: object | None = None
    ) -> EncoderResult:
    ...

```
Because encoder modules can be highly complex, refer to the base `Encoder` class for detailed information about the available methods and their expected behavior. Encoder implementations often contain many helper methods and custom logic, so there is significant flexibility in how they are structured, provided that an `encode()` method is implemented.

When creating a custom encoder, ensure that its `encode()` method remains compatible with the base `Encoder` interface. If your encoder defines its own `encode()` implementation, use the same parameters, variables, and conventions established by the base `Encoder` class to maintain consistency and interoperability with the framework.

---

### Nops

Nops modules generate NOP sleds — sequences of bytes semantically equivalent
to a no-operation that pad the delivery buffer before the payload.

**Base class:** `teralibs.tsf.base.nops.Nops`

**File location:** `modules/nop/...`

**Skeleton:**

```python
from teralibs.tsf.base.nops import ARCH_X86, ARCH_X64, Nops

class TerasploitModule(Nops):
    NAME        = "My NOP Sled"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"
    VERSION     = "1.0"
    RANK        = "normal"

    ARCH            = [ARCH_X86, ARCH_X64]
    SAVE_REGISTERS  = []   # List register names preserved by this sled

    OPTIONS          = []
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS  = []

    def can_avoid(self, badchars: frozenset[int]) -> bool:
        """
        Return False when the NOP byte cannot avoid badchars.

        Override this for any sled with a known fixed byte.  Returning
        False early prevents EncoderFactory from wasting time trying.
        """
        ...

    def generate_sled(self, size: int, badchars: frozenset[int]) -> bytes:
        """
        Return exactly *size* NOP bytes.

        Raise ValueError when the sled cannot be generated.
        """
        ...
```
Never call `generate_sled()` directly from framework code — call `generate(size, badchars)` instead. It wraps `generate_sled()` in a `try/except`, validates that no bad bytes slipped through, and returns a `NopsResult`. `can_avoid()` is a fast pre-filter. Override it when the module uses fixed bytes that cannot be substituted. `SAVE_REGISTERS` is advisory — list register names the sled preserves so callers can choose a sled that doesn't clobber a register they depend on. Nops modules cannot be executed with `run` — use the `generate` command instead.

**Standalone sled generation:**

```
use nop/x86/single_byte
generate 32
generate 32 -b \x00\x0a
```

---

### Evasion

Evasion modules are exploit modules that embed AV/EDR bypass logic directly
in `run()`. They inherit from both `Exploit` and the `Evasion` mixin and are
routed through the same `ExploitDriver` pipeline as exploits.

**Base class:** `teralibs.tsf.base.exploit.Exploit` +
`teralibs.tsf.base.evasion.Evasion` (mixin)

**File location:** `modules/evasion/...`

**Skeleton:**

```python
from teralibs.tsf.base.evasion import Evasion
from teralibs.tsf.base.exploit import (
    ARCH_X64, ARCH_X86,
    PLATFORM_WINDOWS,
    Exploit,
)

class TerasploitModule(Exploit, Evasion):
    NAME        = "My Evasion Module"
    DESCRIPTION = "Short description."
    AUTHOR      = "handle"
    LICENSE     = "BSD-3-CLAUSE"
    VERSION     = "1.0"
    RANK        = "normal"

    ARCH        = [ARCH_X86, ARCH_X64]
    PLATFORM    = [PLATFORM_WINDOWS]
    TARGET      = [(0, "Windows x86/x64 Automatic")]

    PAYLOAD_SPACE = 4096

    # Evasion mixin attributes
    EVASION_TECHNIQUE = "in-memory payload execution"
    NEEDS_CLEANUP     = False   # Set True when run() drops artefacts

    OPTIONS          = ["RHOST", "RPORT"]
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS  = []

    def run(self, ctx):
        ...

    def cleanup(self, ctx):
        """
        Called automatically after run() when NEEDS_CLEANUP = True.

        Remove files, registry keys, or injected threads left by run().
        A broken cleanup() is logged as a warning and never blocks teardown.
        """
        ...
```
The MRO is `TerasploitModule → Exploit → Evasion → Base`. Always put `Exploit` before `Evasion` in the inheritance list. `cleanup(ctx)` is called unconditionally from the driver's `finally` block when `needs_cleanup()` returns `True`. It receives the same `ExploitContext` as `run()`. `EVASION_TECHNIQUE` is displayed in `info` output and module listings. Everything else (payload assembly, TCP handler, session opening) is inherited from `Exploit` unchanged.

---

## Context Objects

Each module type receives a different context object as the first argument to
`run()`. The context provides logging, option access, and type-specific
capabilities. Never reach outside the context into framework internals.

### ExploitContext (`exploit`, `evasion`)

| Method / Attribute | Description |
|---|---|
| `ctx.info(msg)` | Emit an informational log line |
| `ctx.success(msg)` | Emit a success log line |
| `ctx.warning(msg)` | Emit a warning log line |
| `ctx.error(msg)` | Emit an error log line |
| `ctx.get_option(name, scope=None)` | Read an option value from the datastore |
| `ctx.generate_payload()` | Assemble, encode, NOP-pad, and validate the payload |
| `ctx.datastore` | Direct datastore access (prefer `get_option` when possible) |

### AuxiliaryContext (`auxiliary`)

| Method / Attribute | Description |
|---|---|
| `ctx.info(msg)` | Emit an informational log line |
| `ctx.success(msg)` | Emit a success log line |
| `ctx.warning(msg)` | Emit a warning log line |
| `ctx.error(msg)` | Emit an error log line |
| `ctx.get_option(name, scope=None)` | Read an option value from the datastore |

### PostContext (`post`)

| Method / Attribute | Description |
|---|---|
| `ctx.info(msg)` | Emit an informational log line |
| `ctx.success(msg)` | Emit a success log line |
| `ctx.warning(msg)` | Emit a warning log line |
| `ctx.error(msg)` | Emit an error log line |
| `ctx.get_option(name, scope=None)` | Read an option value from the datastore |
| `ctx.session` | The live `ShellSession` — use `send_command()` / `read_output()` |

---

## Ranks

### Exploit, Auxiliary, Post, Nops ranks

Plain string values stored in `RANK`:

| Value | Meaning |
|---|---|
| `"manual"` | Requires significant manual steps; no automation |
| `"low"` | Unreliable; crashes the target frequently |
| `"normal"` | Reliable under specific conditions |
| `"high"` | Reliable against a wide range of targets |
| `"excellent"` | Exploits reliably across all common configurations |

Use `"normal"` as the default for new modules.

### Encoder ranks

`EncoderRank` is an `IntEnum` — higher values are preferred during automatic
encoder selection:

| Value | Integer |
|---|---|
| `EncoderRank.MANUAL` | 0 |
| `EncoderRank.LOW` | 100 |
| `EncoderRank.NORMAL` | 200 |
| `EncoderRank.GOOD` | 300 |
| `EncoderRank.GREAT` | 400 |
| `EncoderRank.EXCELLENT` | 500 |

---

## Platform and Architecture Constants

Import from the base class of the module type you are writing. All base
classes export the same constants.

### Architecture constants

| Constant | Value | Description |
|---|---|---|
| `ARCH_X86` | `"x86"` | IA-32 / 32-bit x86 |
| `ARCH_X64` | `"x64"` | AMD64 / Intel 64 |
| `ARCH_ARM` | `"arm"` | ARM 32-bit (Thumb/ARM) |
| `ARCH_AARCH64` | `"aarch64"` | AArch64 / ARM 64-bit |
| `ARCH_MIPS` | `"mips"` | MIPS 32-bit |
| `ARCH_MIPS64` | `"mips64"` | MIPS 64-bit |
| `ARCH_CMD` | `"cmd"` | Command interpreter (shell string, no shellcode) |

Use `[ARCH_ALL]` when the module is architecture-agnostic.

### Platform constants

| Constant | Value | Description |
|---|---|---|
| `PLATFORM_LINUX` | `"linux"` | Linux (any distro) |
| `PLATFORM_UNIX` | `"unix"` | Generic POSIX / UNIX |
| `PLATFORM_WINDOWS` | `"windows"` | Microsoft Windows |
| `PLATFORM_MACOS` | `"macos"` | Apple macOS / OS X |
| `PLATFORM_BSD` | `"bsd"` | FreeBSD / OpenBSD / NetBSD |
| `PLATFORM_ANDROID` | `"android"` | Android |

Use `[PLATFORM_ALL]` when the module is platform-agnostic.

---

## Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Module class | Always `TerasploitModule` | `class TerasploitModule(Exploit):` |
| File name | `snake_case.py` | `handler.py`, `shikata_ga_nai.py` |
| Directory names | `snake_case` | `windows/smb/`, `linux/x64/` |
| Option keys | `UPPER_SNAKE_CASE` | `RHOST`, `LPORT`, `TIMEOUT` |
| Attribute names | `UPPER_SNAKE_CASE` | `PAYLOAD_SPACE`, `SESSION_TYPES` |
| Private helpers | `_lower_snake_case` | `_tcp_connect`, `_build_rop_chain` |

---

## Checklist

Before submitting a new module, verify:

- [ ] Class is named `TerasploitModule`
- [ ] Inherits from the correct base class
- [ ] `NAME`, `DESCRIPTION`, `AUTHOR`, `LICENSE`, `VERSION`, `RANK` are all set
- [ ] `ARCH` and `PLATFORM` use the correct constants (not raw strings)
- [ ] `PAYLOAD_SPACE` is set explicitly for exploit/evasion modules, or `None`
      to skip the size check
- [ ] All options referenced in `OPTIONS` exist in the registry or are
      registered via `register_options()` in `__init__`
- [ ] `run()` checks option values before using them and emits an `error`
      rather than raising on bad input
- [ ] Long-running loops check `ctx.is_killed()` at each iteration
      (auxiliary modules)
- [ ] `stop()` sets an internal flag when the module holds resources
- [ ] `NEEDS_CLEANUP = True` and `cleanup()` is implemented when `run()`
      drops artefacts on the target (evasion modules)
- [ ] File is placed under the correct `modules/<category>/` subdirectory
- [ ] Module loads cleanly: `use <path>` + `show options` produces no errors
