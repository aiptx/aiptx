# Contributing to AIPTX

Thank you for your interest in contributing to AIPTX! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/aiptx/aiptx/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, AIPTX version)

### Suggesting Features

1. Open a new issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would benefit the project

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest tests/ -v`)
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aiptx.git
cd aiptx

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
ruff check src/

# Run type checking
mypy src/aipt_v2/
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for public functions
- Keep functions focused and concise

## Testing

- Add tests for new features
- Ensure all tests pass before submitting PR
- Maintain or improve code coverage

## Commit Messages

Use clear, descriptive commit messages:

```
feat: Add new WAF bypass technique
fix: Resolve connection timeout issue
docs: Update installation instructions
test: Add tests for credential harvester
refactor: Simplify attack chain builder
```

## Questions?

Feel free to open an issue or reach out to the maintainers.

---

Thank you for contributing to AIPTX!
