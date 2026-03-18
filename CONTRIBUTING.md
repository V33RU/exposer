# Contributing to ExPoser

Contributions are welcome. Please follow the guidelines below.

## Getting Started

```bash
git clone https://github.com/yourorg/exposer.git
cd exposer
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v --cov=exposer
```

## Adding a New Rule

1. Choose the appropriate file in `exposer/rules/` (or create one for a new component type)
2. Subclass `BaseRule` and implement the `check()` method
3. Assign a unique `rule_id` (next available EXP-XXX), `title`, `severity`, `cwe`, `description`, `remediation`, and `references`
4. Register the rule in `exposer/cli.py` inside `get_all_rules()`
5. Add an entry to the vulnerability table in `README.md`
6. Write a test in `tests/rules/`

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new rules
- Run `pytest` and ensure all tests pass before submitting
- Follow existing code style (no linter config yet — match the surrounding code)

## Reporting Issues

Open an issue on GitHub with:
- ExPoser version (`exposer --version`)
- APK details (obfuscated if needed)
- Full error output or description of incorrect findings
