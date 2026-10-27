# Password Generator PRD

## Summary

Create a secure, dependable password generator that can be used interactively, from command-line automation, and through an optional local-only web lab. The product must make each password's character requirements explicit, preserve cryptographic randomness, and prevent invalid configuration from producing misleading results.

## Goals

- Generate cryptographically secure passwords using `secrets`.
- Guarantee at least one character from every enabled character category.
- Support lowercase letters, uppercase letters, digits, and symbols independently.
- Allow users to exclude ambiguous characters.
- Support interactive use and non-interactive command-line use.
- Report the password length and estimated entropy accurately.
- Validate all values before generating passwords.
- Keep the implementation dependency-free and easy to reuse from Python.
- Offer a local web lab where users can generate passwords and try sample values in a clearly labeled pretend sign-up form.
- Keep demo form values in the browser; do not create accounts, transmit form values, or persist passwords.

## User Stories

1. As an end user, I can run the program and choose password options through prompts.
2. As an automation user, I can pass options to create one or more passwords without prompts.
3. As a security-conscious user, I can choose exactly which character categories appear.
4. As a user copying passwords, I can optionally exclude visually ambiguous characters.
5. As a developer, I can call a generator API that raises clear errors for invalid settings.
6. As a learner, I can run a local website to experiment with password strength without sending credentials to a real service.

## Functional Requirements

- The default password length is 12 characters.
- `--length`, `--count`, and `--exclude` or equivalent options must be accepted by the CLI.
- Character category flags must disable the corresponding category.
- `--count` must be a positive integer; values larger than 10,000 must be rejected to avoid accidental output floods.
- The selected character pool must never be empty.
- The generated password length must be at least the number of enabled, non-empty character categories.
- Generated passwords must contain at least one character from every enabled category.
- Interactive mode must accept Enter for defaults and reject invalid input gracefully.
- `--json` must output machine-readable results.
- `--no-strength` must suppress strength labels.
- In automation mode, all options must be configurable without interactive prompts.
- Empty ambiguous-filtered categories must not be silently treated as configured categories.
- Strength estimates must use the exact character pool selected for generation, rather than inferring categories from the produced password.

## Non-Functional Requirements

- Python standard library only.
- Cryptographically secure random generation through `secrets`; no use of `random` for passwords.
- Clear, actionable error messages and non-zero exit status for invalid arguments.
- Public functions should use type annotations and raise `ValueError` for invalid configuration.
- Program behavior must not expose passwords to shell history, logs, or persistent storage.
- The web lab must bind to loopback, use no third-party assets or services, and never submit or save demo form values.

## Acceptance Criteria

- Running `python password-gen.py` opens a usable interactive flow.
- Running `python password-gen.py --length 24 --count 3` prints three distinct or effectively independent passwords of exactly 24 characters.
- Running `python password-gen.py --length 1 --no-uppercase --no-digits --no-symbols` succeeds only when lowercase is enabled.
- Invalid combinations return a clear error and exit status 1 or 2.
- JSON output is valid JSON and contains password, length, entropy_bits, and strength fields.
- Generated passwords always contain one character from each enabled category.
- Running `python password-lab.py` serves the interactive lab on loopback without installing packages.
- The web lab clearly warns against real credentials and does not send its demo form fields to the server.

## Out of Scope

- Persisting passwords or writing password files.
- Browser integration or password-manager APIs.
- K-anonymity checks or breach-database integration.
- Browser integration or password-manager APIs.
- Rigorous cryptographic strength certification.
