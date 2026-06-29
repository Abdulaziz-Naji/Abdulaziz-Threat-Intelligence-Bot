# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active  |

---

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **do not open a public GitHub issue**.

Instead, please report it privately:

1. **Email**: Open a private security advisory via GitHub:  
   [GitHub Security Advisories](https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot/security/advisories/new)

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

3. **Response time**: I aim to acknowledge reports within **48 hours** and provide a fix within **7 days** for critical issues.

---

## Security Design

- All API keys are loaded exclusively from environment variables (`.env`)
- No secrets are ever committed to the repository
- The bot supports user authorization via `AUTHORIZED_USERS` to restrict access
- No user data is transmitted to third parties beyond the configured threat intelligence APIs
- Database files (`.db`) are excluded from version control

---

## Scope

In scope for security reports:
- API key exposure or leakage
- Authentication bypass (unauthorized bot access)
- Remote code execution via malicious file uploads
- SQL injection in the database layer
- Sensitive data disclosure in bot responses

Out of scope:
- False positive/negative threat detections
- API rate limits from third-party services
- Missing features or bugs that do not have security impact

---

## Disclosure Policy

We follow **responsible disclosure**. Please allow reasonable time for a fix before public disclosure.
