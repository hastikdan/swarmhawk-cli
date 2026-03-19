# Contributing to SwarmHawk

SwarmHawk is open-source because the security community makes it better. Every new check, template set, or integration directly benefits practitioners who use it in the field.

## Ways to Contribute

### High-impact contributions

- **Vulnerability checks** — extend `exploit.py` with new detection logic
- **Nuclei template curation** — curated template lists for specific stacks (WordPress, SAP, Laravel, etc.)
- **Recon sources** — additional subdomain enumeration or asset discovery methods
- **Integrations** — Jira, Slack, Splunk, PagerDuty output targets
- **Report themes** — alternative HTML/PDF templates

### Lower-lift contributions

- Fix a bug (check [open issues](https://github.com/swarmhawk-ai/swarmhawk/issues))
- Improve test coverage
- Improve documentation or add examples
- Translate docs

---

## Getting Started

### 1. Fork and clone

```bash
git clone https://github.com/YOUR_FORK/swarmhawk.git
cd swarmhawk
```

### 2. Install in dev mode

```bash
pip install -e ".[dev]"
```

### 3. Run the tests

```bash
pytest tests/ -v
```

All 27 tests should pass with no external API keys or tools required (mock mode is used in tests).

### 4. Make your change

- Keep changes focused — one PR per feature or fix
- Follow the existing code style (Black + Ruff enforced in CI)
- Add or update tests for any new behavior

### 5. Run lint and format

```bash
ruff check swarmhawk/
black swarmhawk/
```

### 6. Open a PR

Open a PR against `main`. The CI will run tests on Python 3.11 and 3.12 automatically. Describe what your change does and why.

---

## Adding a Vulnerability Check

The cleanest extension point is `exploit.py`. The `ExploitAgent` has a `_validate_finding()` method and a 3-layer pipeline you can plug into.

For new Nuclei template curation, add a focused template list to `exploit.py` or propose a new file `templates/` with a curated YAML list targeting a specific tech stack.

Example structure for a new check module:

```python
# In exploit.py or a new checks/ module

def check_my_vulnerability(asset) -> Optional[Finding]:
    """
    Detect XYZ vulnerability on an asset.
    Returns a Finding or None.
    """
    # Your detection logic here
    ...
```

Please include:
- A test in `tests/test_swarmhawk.py`
- A description of what the check detects
- CVE reference if applicable
- Confidence level (for the 3-layer pipeline)

---

## Adding a Recon Source

`recon.py` defines the `ReconAgent`. New subdomain discovery sources, DNS resolvers, or asset enrichment methods can be added there.

Any new source should:
- Degrade gracefully when the underlying tool isn't installed (fall back to existing sources)
- Work in mock mode (controlled by `self.mock_mode`)
- Add its results to the `Asset` list returned by `recon.run()`

---

## Code Style

- **Formatter**: [Black](https://black.readthedocs.io/) (line length 88)
- **Linter**: [Ruff](https://docs.astral.sh/ruff/)
- **Types**: Type hints encouraged but not enforced everywhere
- **Docstrings**: Module-level and class-level docstrings required; method docstrings for non-obvious logic

Both are checked in CI. Run them locally before opening a PR:

```bash
black swarmhawk/
ruff check swarmhawk/
```

---

## Commit Messages

Use conventional commits:

```
feat: add WordPress plugin enumeration to recon
fix: handle NVD rate limit retry correctly
docs: add example for custom scope ledger
test: add exploit agent integration test
```

---

## Legal

By contributing to SwarmHawk you agree that:

1. Your contribution is your own original work
2. You grant the project maintainers a perpetual, worldwide, non-exclusive, royalty-free license to use, reproduce, modify, and distribute your contribution under the MIT License
3. You will not contribute code designed to facilitate unauthorized access to systems

All contributions must be for **defensive security**, **research**, or **authorized testing** purposes only.

---

## Questions?

Open a [GitHub Discussion](https://github.com/swarmhawk-ai/swarmhawk/discussions) or file an [issue](https://github.com/swarmhawk-ai/swarmhawk/issues).
