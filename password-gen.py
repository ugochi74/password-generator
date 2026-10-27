"""
Password Generator

Generates cryptographically secure random passwords using Python's `secrets`
module (not `random` — `random` is predictable enough over time that it's
unsuitable for anything security-related; `secrets` is designed specifically
for this).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from collections.abc import Sequence
import json
import math
import secrets
import string
import sys


CHARACTER_SETS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}
AMBIGUOUS_CHARS = "il1LoO0"
MAX_PASSWORD_LENGTH = 4096
MAX_PASSWORD_COUNT = 10_000


@dataclass(frozen=True)
class PasswordOptions:
    length: int = 12
    count: int = 1
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = False

    def character_sets(self) -> tuple[str, ...]:
        enabled = (
            ("lowercase", self.use_lowercase),
            ("uppercase", self.use_uppercase),
            ("digits", self.use_digits),
            ("symbols", self.use_symbols),
        )
        sets = tuple(
            filter_ambiguous(CHARACTER_SETS[name]) if self.avoid_ambiguous else CHARACTER_SETS[name]
            for name, included in enabled
            if included
        )
        if not sets:
            raise ValueError("At least one character type must be selected.")
        return sets

    def validate(self) -> None:
        sets = self.character_sets()
        if not 1 <= self.length <= MAX_PASSWORD_LENGTH:
            raise ValueError(f"Length must be between 1 and {MAX_PASSWORD_LENGTH}.")
        if self.length < len(sets):
            raise ValueError(
                f"Length must be at least {len(sets)} to include one of each "
                "selected character type."
            )
        if not 1 <= self.count <= MAX_PASSWORD_COUNT:
            raise ValueError(f"Count must be between 1 and {MAX_PASSWORD_COUNT}.")

    def character_pool(self) -> str:
        self.validate()
        return "".join(dict.fromkeys("".join(self.character_sets())))


def filter_ambiguous(characters: str) -> str:
    return "".join(character for character in characters if character not in AMBIGUOUS_CHARS)


def build_character_pool(
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool,
) -> str:
    """Combine selected character sets into a deduplicated pool."""
    options = PasswordOptions(
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        avoid_ambiguous=avoid_ambiguous,
    )
    return options.character_pool()


def generate_password(
    length: int = 12,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """Generate a password with at least one character from each enabled set."""
    options = PasswordOptions(
        length=length,
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        avoid_ambiguous=avoid_ambiguous,
    )
    options.validate()
    password_chars = [secrets.choice(characters) for characters in options.character_sets()]
    pool = options.character_pool()
    password_chars.extend(secrets.choice(pool) for _ in range(length - len(password_chars)))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def estimate_strength(password: str, pool: str | None = None) -> tuple[int, str]:
    """Estimate strength from the exact character pool used to make the password."""
    if pool is None:
        pool = "".join(
            characters
            for characters, active in (
                (string.ascii_lowercase, any(char in string.ascii_lowercase for char in password)),
                (string.ascii_uppercase, any(char in string.ascii_uppercase for char in password)),
                (string.digits, any(char in string.digits for char in password)),
                (string.punctuation, any(char in string.punctuation for char in password)),
            )
            if active
        )

    entropy_bits = len(password) * math.log2(len(pool)) if password and pool else 0
    if entropy_bits < 40:
        label = "Weak"
    elif entropy_bits < 60:
        label = "Moderate"
    elif entropy_bits < 80:
        label = "Strong"
    else:
        label = "Very Strong"
    return round(entropy_bits), label


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question, accepting y/n/yes/no/blank (blank = default)."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        answer = input(prompt + suffix).strip().lower()
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer y or n.")


def ask_positive_integer(prompt: str, default: int, maximum: int) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
            if 1 <= value <= maximum:
                return value
        except ValueError:
            pass
        print(f"Please enter a whole number from 1 to {maximum}.")


def interactive_options() -> PasswordOptions:
    print("=== Password Generator ===")
    length = ask_positive_integer("Password length", 12, MAX_PASSWORD_LENGTH)
    use_lowercase = ask_yes_no("Include lowercase letters?", True)
    use_uppercase = ask_yes_no("Include uppercase letters?", True)
    use_digits = ask_yes_no("Include digits?", True)
    use_symbols = ask_yes_no("Include symbols?", True)
    avoid_ambiguous = ask_yes_no("Avoid ambiguous characters (l, 1, I, O, 0)?", False)
    options = PasswordOptions(
        length=length,
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        avoid_ambiguous=avoid_ambiguous,
    )
    options.validate()
    count = ask_positive_integer("How many passwords", 1, MAX_PASSWORD_COUNT)
    return PasswordOptions(**{**options.__dict__, "count": count})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate cryptographically secure passwords.")
    parser.add_argument("--length", type=int, default=12, help="password length (default: 12)")
    parser.add_argument("--count", type=int, default=1, help="number of passwords (default: 1)")
    parser.add_argument("--no-lowercase", action="store_true", help="exclude lowercase letters")
    parser.add_argument("--no-uppercase", action="store_true", help="exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="exclude symbols")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="exclude visually ambiguous characters")
    parser.add_argument("--interactive", action="store_true", help="use prompts instead of command options")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--no-strength", action="store_true", help="omit human-readable strength labels")
    return parser


def render_passwords(options: PasswordOptions, as_json: bool, include_strength: bool) -> None:
    pool = options.character_pool()
    results = []
    for _ in range(options.count):
        password = generate_password(
            options.length,
            options.use_lowercase,
            options.use_uppercase,
            options.use_digits,
            options.use_symbols,
            options.avoid_ambiguous,
        )
        entropy_bits, strength = estimate_strength(password, pool)
        results.append({
            "password": password,
            "length": options.length,
            "entropy_bits": entropy_bits,
            "strength": strength,
        })

    if as_json:
        print(json.dumps(results if options.count > 1 else results[0], indent=2))
        return

    for index, result in enumerate(results, start=1):
        suffix = f"  ({result['strength']}, ~{result['entropy_bits']} bits)" if include_strength else ""
        prefix = f"{index}. " if options.count > 1 else ""
        print(f"{prefix}{result['password']}{suffix}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(arguments)

    try:
        if args.interactive or not arguments:
            options = interactive_options()
        else:
            options = PasswordOptions(
                length=args.length,
                count=args.count,
                use_lowercase=not args.no_lowercase,
                use_uppercase=not args.no_uppercase,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                avoid_ambiguous=args.exclude_ambiguous,
            )
            options.validate()
        render_passwords(options, args.json, not args.no_strength)
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


if __name__ == "__main__":
    main()