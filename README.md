# M5 — Frida Hook Generator

Generate **real Frida JavaScript instrumentation hooks** from a declarative
JSON spec, with an offline structural JS validator. No Frida device or node is
needed to generate or validate — fully stdlib-only.

## What genuinely works

- **Java hooks** — emits `Java.perform { Java.use(...).<method>.implementation
  = ... }` with overload selection, arg logging and return-value logging.
- **Native hooks** — emits `Interceptor.attach(...)` on exports resolved via
  `Module.findExportByName(...)`.
- **Offline JS structural validator** — balances `()`, `[]`, `{}` while
  correctly ignoring single/double-quoted strings and comments; catches
  unbalanced delimiters without requiring node.
- **CLI** — `generate`, `validate`, `demo` subcommands with clean exit codes.

## Usage

```bash
python3 frida_gen.py --help

# Generate a script + metadata from a JSON spec (validated by default)
python3 frida_gen.py generate spec.json -o reports/frida --validate

# Validate an arbitrary JS file structurally
python3 frida_gen.py validate hook.js

# Offline demo — generates the bundled spec and validates (exits 0)
python3 frida_gen.py demo
```

A spec looks like:

```json
{
  "package": "com.lab.app",
  "hooks": [
    {"type": "java", "class": "com.lab.app.core.AuthManager",
     "method": "login", "params": ["java.lang.String", "java.lang.String"],
     "on_enter": {"log_args": true, "annotate": "AUTH-LOGIN"}},
    {"type": "native", "module": "libnative.so",
     "symbol": "crypto_box_decrypt", "on_enter": {"log": "NATIVE-CRYPTO"}}
  ]
}
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Fully offline — 15 stdlib unittest cases cover spec validation, JS generation,
the structural validator, and CLI exit codes.

## Live Lab Test Plan

1. Run `python3 frida_gen.py demo` in an offline lab VM; confirm it prints the
   generated script byte count, hook counts and `JS structural validation: OK`,
   then exits 0.
2. Author your own spec JSON and run `generate spec.json -o out --validate`;
   confirm `script.js` and `metadata.json` are written and validation reports OK.
3. Take the generated `script.js` and pass it through `validate script.js` to
   confirm the standalone validator also passes.
4. Only ever attach these hooks to applications you own or have explicit
   written authorization to instrument, in a lab/emulator.

## Metrics

- Generator: Java + native hook emission from JSON spec.
- Validator: balanced-delimiter JS structural check (no node dependency).
- Test count: 15 stdlib unittest cases (see `tests/`).
- Dependencies: Python 3 stdlib only (`argparse`, `json`, `re`, `os`).
- Offline demo: exits 0, produces a real validated Frida script.

## IMPORTANT: Read before use.

This tool is for **educational and authorized security testing only**. You MUST
have explicit written permission from the app owner before instrumenting any
application. Unauthorized modification of application behavior may violate the
Computer Fraud and Abuse Act (CFAA), the DMCA, and state computer-crime laws.
Only ever hook applications you own or have written authorization to test, in a
controlled lab or emulator. The author is not responsible for misuse.

## License

MIT — see `LICENSE`.
