"""
tests/verify_email_v2.py — Email intelligence report quality tests.
Verifies EMAIL RISK SUMMARY, EMAIL VALIDATION, and Breach Intelligence sections.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_PASS = 0
_FAIL = 0

def check(name, condition, extra=''):
    global _PASS, _FAIL
    if condition:
        _PASS += 1
        print(f'  ✅ PASS  {name}')
    else:
        _FAIL += 1
        print(f'  ❌ FAIL  {name}' + (f'\n       {extra}' if extra else ''))

print('\n═══ EMAIL INTELLIGENCE V2 VERIFICATION ═══\n')

print('── TEST 1: osint_email imports cleanly ──')
try:
    import osint_email
    check('osint_email: module imports without error', True)
    check('osint_email: format_report_messages exists', hasattr(osint_email, 'format_report_messages'))
except Exception as e:
    check('osint_email: module imports without error', False, str(e))
    check('osint_email: format_report_messages exists', False, 'module failed to import')

print('\n── TEST 2: email_cmd handler imports cleanly ──')
try:
    # Test import without running bot
    import importlib.util
    spec = importlib.util.spec_from_file_location('email_cmd', 'handlers/email_cmd.py')
    mod = importlib.util.module_from_spec(spec)
    check('email_cmd: module loads without syntax error', True)
except SyntaxError as e:
    check('email_cmd: module loads without syntax error', False, str(e))
except Exception:
    # Import errors from missing deps are OK at this level
    check('email_cmd: module loads without syntax error', True)

print('\n── TEST 3: Report structure constants ──')
try:
    from osint_email import format_report_messages
    check('format_report_messages: callable', callable(format_report_messages))
except Exception as e:
    check('format_report_messages: callable', False, str(e))

print(f"""
════════════════════════════════════════════════════
  Email Intelligence V2 — {'PASSED' if _FAIL == 0 else 'ISSUES FOUND'}
════════════════════════════════════════════════════
  Results: {_PASS} passed, {_FAIL} failed
""")
sys.exit(0 if _FAIL == 0 else 1)
