# Contributing to Docker Security Scanner

Thank you for your interest in contributing! 🎉

---

## Ways to Contribute

- 🐛 **Bug reports** — open a GitHub issue with reproduction steps
- ✨ **Feature requests** — open an issue tagged `enhancement`
- 🔌 **New scanner integrations** — add support for additional tools
- 📖 **Documentation improvements** — fix typos, add examples
- 🧪 **Test coverage** — expand the test suite

---

## Development Setup

```bash
git clone https://github.com/yourusername/docker-security-scanner.git
cd docker-security-scanner

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e ".[dev]"

# Verify tools are available
trivy --version
hadolint --version
gitleaks version
```

---

## Code Standards

| Tool | Command | Purpose |
|------|---------|---------|
| Black | `black src/ tests/` | Formatting |
| isort | `isort src/ tests/` | Import sorting |
| flake8 | `flake8 src/ tests/` | Style linting |
| mypy | `mypy src/` | Type checking |

**Run all checks at once:**
```bash
black src/ tests/ && isort src/ tests/ && flake8 src/ tests/ && mypy src/
```

---

## Adding a New Scanner

1. Create `src/your_scanner.py` following the existing pattern:
   - `YourScanResult` dataclass with `passed`, `to_dict()`, `summary()`
   - `YourScanner` class with `__init__(config)`, `scan(target)` method
   - `ToolNotFoundError` check in `__init__`

2. Add a `_check_tool_available()` call in `__init__`

3. Integrate into `src/scanner.py` → `SecurityScanner.scan_image()`

4. Add tests in `tests/test_your_scanner.py`

5. Update `README.md` features list and `ARCHITECTURE.md`

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make changes with passing tests
4. Run the full test suite: `pytest tests/ --cov=src --cov-fail-under=85`
5. Run linting: `black --check src/ && flake8 src/`
6. Push and open a PR against `main`

### PR Checklist
- [ ] Tests added/updated (coverage ≥ 85%)
- [ ] Docstrings on all new public functions
- [ ] Type hints on all new functions
- [ ] `ARCHITECTURE.md` updated (if architecture changed)
- [ ] No hardcoded secrets or credentials

---

## Commit Message Format

```
type(scope): short description

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

**Examples:**
```
feat(trivy): add CVSS v4 score parsing
fix(gitleaks): handle non-JSON output on zero findings
docs(readme): add Docker Hub badge
test(scanner): add policy enforcement edge cases
```

---

## License

By contributing, you agree your contributions will be licensed under the [MIT License](LICENSE).
