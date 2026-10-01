# Contributing to Phantom Recon

Thank you for your interest in contributing to **Phantom Recon**! 🔥 We welcome contributions from the security community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## 📜 Code of Conduct

- Be respectful and constructive in all interactions
- All tools and features must be designed for **authorized testing only**
- Never include functionality intended for malicious use
- Follow responsible disclosure practices

---

## 🚀 Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/phantom-recon.git
   cd phantom-recon
   ```
3. **Add upstream** remote:
   ```bash
   git remote add upstream https://github.com/tahir/phantom-recon.git
   ```

---

## 🔧 Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate      # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

---

## ✏️ Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our [code style](#code-style)

3. Write tests for new functionality

4. Commit with clear messages:
   ```bash
   git commit -m "feat: add new scanning module for XYZ"
   ```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Adding/fixing tests
- `refactor:` — Code refactoring
- `style:` — Formatting changes
- `chore:` — Build/tooling changes

---

## 🎨 Code Style

We use the following tools for code quality:

- **Black** for code formatting (line length: 100)
- **Ruff** for linting
- **MyPy** for type checking

```bash
# Format code
black phantom_recon/ tests/

# Lint
ruff check phantom_recon/ tests/

# Type check
mypy phantom_recon/
```

### Guidelines

- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Include `⚠️ DISCLAIMER` comments in modules that perform active testing
- Keep functions focused and under 50 lines where possible
- Use meaningful variable names

---

## 🧪 Testing

All contributions **must** include tests:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=phantom_recon --cov-report=html

# Run specific test file
pytest tests/test_scanner.py -v
```

### Test Guidelines

- Place tests in `tests/` directory
- Name test files `test_*.py`
- Use `pytest` fixtures for setup/teardown
- Mock external calls (network, DNS, etc.)
- Aim for >80% code coverage on new code

---

## 📬 Pull Request Process

1. Update your branch with latest upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Ensure all tests pass: `pytest`

3. Ensure code quality: `black . && ruff check .`

4. Push your branch: `git push origin feature/your-feature-name`

5. Open a Pull Request with:
   - Clear title describing the change
   - Description of what was changed and why
   - Link to any related issues
   - Screenshots if UI-related

6. Wait for review — maintainers will review within 48 hours

---

## 🐛 Reporting Issues

When reporting bugs, please include:

- **Python version**: `python --version`
- **OS**: Windows/Linux/macOS + version
- **Steps to reproduce**: Minimal example
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Error output**: Full traceback if applicable

Use the [GitHub Issues](https://github.com/tahir/phantom-recon/issues) page.

---

## 💡 Feature Requests

We welcome feature suggestions! Please:

1. Check existing issues to avoid duplicates
2. Describe the use case clearly
3. Explain why it would benefit the project
4. If possible, outline a proposed implementation

---

Thank you for contributing to making security testing tools better! 🔐
