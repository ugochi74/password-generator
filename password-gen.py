"""
Password Generator

Generates cryptographically secure random passwords using Python's `secrets`
module (not `random` — `random` is predictable enough over time that it's
unsuitable for anything security-related; `secrets` is designed specifically
for this).
"""

import secrets
import string


CHARACTER_SETS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}

# Characters that are easy to visually confuse (1/l/I, 0/O, etc.)
AMBIGUOUS_CHARS = "il1LoO0"


def build_character_pool(use_lowercase, use_uppercase, use_digits, use_symbols, avoid_ambiguous):
    """Combine the selected character sets into one pool to draw from."""
    pool = ""
    if use_lowercase:
        pool += CHARACTER_SETS["lowercase"]
    if use_uppercase:
        pool += CHARACTER_SETS["uppercase"]
    if use_digits:
        pool += CHARACTER_SETS["digits"]
    if use_symbols:
        pool += CHARACTER_SETS["symbols"]

    if not pool:
        raise ValueError("At least one character type must be selected.")

    if avoid_ambiguous:
        pool = "".join(ch for ch in pool if ch not in AMBIGUOUS_CHARS)

    return pool


def generate_password(length=12, use_lowercase=True, use_uppercase=True,
                       use_digits=True, use_symbols=True, avoid_ambiguous=False):
    """
    Generate a random password of the given length, guaranteeing at least
    one character from each selected category (so requesting symbols
    doesn't mean you might get zero of them by chance).
    """
    if length < 1:
        raise ValueError("Length must be at least 1.")

    selected_sets = []
    if use_lowercase:
        selected_sets.append(CHARACTER_SETS["lowercase"])
    if use_uppercase:
        selected_sets.append(CHARACTER_SETS["uppercase"])
    if use_digits:
        selected_sets.append(CHARACTER_SETS["digits"])
    if use_symbols:
        selected_sets.append(CHARACTER_SETS["symbols"])

    if not selected_sets:
        raise ValueError("At least one character type must be selected.")

    if avoid_ambiguous:
        selected_sets = ["".join(ch for ch in s if ch not in AMBIGUOUS_CHARS) for s in selected_sets]
        selected_sets = [s for s in selected_sets if s]  # drop any set emptied entirely

    if length < len(selected_sets):
        raise ValueError(
            f"Length must be at least {len(selected_sets)} to include "
            f"one of each selected character type."
        )

    full_pool = build_character_pool(use_lowercase, use_uppercase, use_digits, use_symbols, avoid_ambiguous)

    # Guarantee at least one character from each selected category
    password_chars = [secrets.choice(s) for s in selected_sets]

    # Fill the rest randomly from the combined pool
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(full_pool) for _ in range(remaining)]

    # Shuffle so the guaranteed characters aren't predictably at the start
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def estimate_strength(password):
    """
    Rough password strength estimate based on entropy (bits of randomness).
    This is a simplification for user feedback, not a rigorous security audit.
    """
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    if pool_size == 0:
        return 0, "N/A"

    import math
    entropy_bits = len(password) * math.log2(pool_size)

    if entropy_bits < 40:
        label = "Weak"
    elif entropy_bits < 60:
        label = "Moderate"
    elif entropy_bits < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    return round(entropy_bits), label


def ask_yes_no(prompt, default=True):
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


def ask_length():
    """Ask for password length, validating it's a positive integer."""
    while True:
        raw = input("Password length [12]: ").strip()
        if raw == "":
            return 12
        try:
            value = int(raw)
            if value < 1:
                print("Length must be at least 1.")
                continue
            return value
        except ValueError:
            print("Please enter a whole number.")


def main():
    print("=== Password Generator ===\n")

    while True:
        print("\n1. Generate a password")
        print("2. Generate multiple passwords")
        print("3. Quit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            length = ask_length()
            use_lower = ask_yes_no("Include lowercase letters?", default=True)
            use_upper = ask_yes_no("Include uppercase letters?", default=True)
            use_digits = ask_yes_no("Include digits?", default=True)
            use_symbols = ask_yes_no("Include symbols?", default=True)
            avoid_ambiguous = ask_yes_no("Avoid ambiguous characters (l, 1, I, O, 0)?", default=False)

            try:
                password = generate_password(
                    length, use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous
                )
                bits, label = estimate_strength(password)
                print(f"\nGenerated password: {password}")
                print(f"Estimated strength: {label} (~{bits} bits of entropy)")
            except ValueError as e:
                print(f"\nError: {e}")

        elif choice == "2":
            count = input("How many passwords? [5]: ").strip()
            count = int(count) if count.isdigit() and int(count) > 0 else 5

            length = ask_length()
            use_lower = ask_yes_no("Include lowercase letters?", default=True)
            use_upper = ask_yes_no("Include uppercase letters?", default=True)
            use_digits = ask_yes_no("Include digits?", default=True)
            use_symbols = ask_yes_no("Include symbols?", default=True)
            avoid_ambiguous = ask_yes_no("Avoid ambiguous characters (l, 1, I, O, 0)?", default=False)

            try:
                print()
                for i in range(count):
                    password = generate_password(
                        length, use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous
                    )
                    bits, label = estimate_strength(password)
                    print(f"{i + 1}. {password}  ({label}, ~{bits} bits)")
            except ValueError as e:
                print(f"\nError: {e}")

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice! Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()