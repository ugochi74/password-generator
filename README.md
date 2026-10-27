# Password Generator

A dependency-free Python password generator that uses `secrets` for cryptographically secure randomness. It supports interactive prompts, command-line automation, JSON output, configurable character categories, and ambiguous-character filtering.

## Requirements

- Python 3.10 or newer

## Quick Start

Run the interactive prompts:

```bash
python password-gen.py
```

Run the local Password Security Lab:

```bash
python password-lab.py
```

Open the local address printed in the terminal (by default, `http://127.0.0.1:8000`). The lab contains a password generator and a pretend sign-up form for trying generated or sample passwords. It binds only to your computer, has no external application dependencies, and does not submit or store form values. **Do not enter real passwords or personal information.** Stop the server with `Ctrl+C`.

Choose another local port if port 8000 is already in use:

```bash
python password-lab.py --port 8080
```

Generate one 24-character password:

```bash
python password-gen.py --length 24
```

Generate three passwords while excluding lowercase and ambiguous characters:

```bash
python password-gen.py --length 24 --count 3 --no-lowercase --exclude-ambiguous
```

Generate machine-readable output:

```bash
python password-gen.py --length 32 --count 2 --json
```

## Options

- `--length INTEGER`: Password length, from 1 to 4096 (default: 12).
- `--count INTEGER`: Number of passwords, from 1 to 10,000 (default: 1).
- `--no-lowercase`: Exclude lowercase letters.
- `--no-uppercase`: Exclude uppercase letters.
- `--no-digits`: Exclude digits.
- `--no-symbols`: Exclude symbols.
- `--exclude-ambiguous`: Exclude characters such as `l`, `1`, `I`, `O`, and `0`.
- `--interactive`: Always use prompts.
- `--json`: Emit password, length, entropy, and strength as JSON.
- `--no-strength`: Omit strength labels from human-readable output.
- `-h`, `--help`: Display CLI help.

At least one character category must remain enabled, and the length must be large enough to guarantee one character from every enabled category.

## Python API

The module can be loaded directly from its filename with `importlib`. The public functions are `generate_password`, `estimate_strength`, and `build_character_pool`; `PasswordOptions` provides reusable configuration.

```python
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("password_gen", "password-gen.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
password = module.generate_password(length=24, avoid_ambiguous=True)
```

`PasswordOptions` provides a reusable, validated configuration:

```python
options = module.PasswordOptions(length=32, count=5, avoid_ambiguous=True)
options.validate()
pool = options.character_pool()
```

Invalid combinations raise `ValueError` with an actionable message.

## Security Notes

Passwords are assembled with `secrets.choice`, never the predictable `random` module. The generator guarantees at least one character from every enabled category, then securely shuffles the assembled characters.

The strength field is a rough entropy estimate based on the selected character pool. It is useful feedback, not a guarantee about a target system's storage or authentication policies.

The local lab binds to `127.0.0.1`, does not use external scripts or services, and keeps demo-form input in the browser. The form is not an account-creation flow. The lab API receives generation settings only; generated passwords are returned to the browser and are not written to files or logs.

## Product Requirements

See [PRD.md](PRD.md) for goals, acceptance criteria, and non-goals.
