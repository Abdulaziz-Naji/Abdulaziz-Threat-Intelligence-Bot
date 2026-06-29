# Contributing to Abdulaziz Threat Intelligence Bot

Thank you for your interest in contributing! This document explains how to participate.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Abdulaziz-threat-intelligence-bot.git
   cd Abdulaziz-threat-intelligence-bot
   ```
3. **Create a branch** for your change:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Set up** the environment:
   ```bash
   python -m venv venv
   source venv/bin/activate      # Linux/macOS
   venv\Scripts\activate         # Windows
   pip install -r requirements.txt
   cp .env.example .env
   # Fill in your API keys in .env
   ```

---

## Development Guidelines

### Code Style
- Follow PEP 8
- Use type hints where practical
- Keep functions focused — one responsibility per function
- Avoid print() debugging in production code

### Report Output Rules (important)
- **Never** show internal API status codes to users (e.g., `HTTP 200`, `Key Missing`)
- **Never** show debug messages or stack traces in bot responses
- Keep reports compact — fit within a single Telegram screen where possible
- Show evidence, not data dumps

### Commit Messages
Use clear, descriptive commit messages:
```
feat: add HIBP breach lookup to /email command
fix: correct OTX pulse count display
docs: update deployment guide for Ubuntu 24.04
```

---

## Running Tests

Before submitting a PR, run the full test suite:

```bash
python -m pytest tests/ -v
```

Or run individual verification scripts:

```bash
python tests/verify_phase15.py
python tests/verify_email_v2.py
python tests/verify_phase14.py
```

All tests must pass before a PR can be merged.

---

## Submitting a Pull Request

1. Ensure all tests pass
2. Update `CHANGELOG.md` under `[Unreleased]`
3. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Open a Pull Request on GitHub with a clear description of your changes

---

## Reporting Issues

Use the [GitHub Issues](https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot/issues) page.

Please include:
- Bot command used
- Expected behavior
- Actual behavior
- Any error messages (remove API keys before sharing)

---

## Code of Conduct

Be respectful and constructive. This is a security-focused project — responsible disclosure matters.
