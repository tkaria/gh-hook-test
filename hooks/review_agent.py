#!/usr/bin/env python3
"""Pre-commit review agent: checks staged changes for secrets, forbidden files, and code smells."""

import os
import re
import subprocess
import sys

# --- Configuration ---

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

FORBIDDEN_PATTERNS = [
    r"^\.env$",
    r"^\.env\..+",
    r"(^|/)\.DS_Store$",
    r"(^|/)Thumbs\.db$",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"(^|/)node_modules/",
    r"(^|/)__pycache__/",
    r"\.pyc$",
    r"(^|/)credentials\.json$",
    r"\.keystore$",
]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(aws_secret_access_key|aws_secret)\s*=\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Key"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    (r"(?i)(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}", "Stripe API Key"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token"),
    (r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "Private Key"),
    (r"(?i)(api_key|apikey|api_secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "API Key Assignment"),
    (r"(?i)(secret|secret_key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "Secret Assignment"),
    (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded Password"),
    (r"(?i)(mongodb|postgres|mysql|redis)://[^\s'\"]+:[^\s'\"]+@", "Connection String with Credentials"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token"),
    (r"(?i)bearer\s+[A-Za-z0-9_\-.~+/]+=*", "Bearer Token"),
]

WARN_PATTERNS = [
    (r"\bTODO\b", "TODO marker"),
    (r"\bFIXME\b", "FIXME marker"),
    (r"\bHACK\b", "HACK marker"),
    (r"\bimport\s+pdb\b", "Python debugger import"),
    (r"\bpdb\.set_trace\(\)", "Python debugger call"),
    (r"\bbreakpoint\(\)", "Python breakpoint"),
    (r"\bdebugger\s*;", "JS debugger statement"),
    (r"\bconsole\.log\b", "console.log statement"),
    (r"(?<!\d)127\.0\.0\.1(?!\d)", "Hardcoded localhost IP"),
    (r"(?<!\d)0\.0\.0\.0(?!\d)", "Hardcoded 0.0.0.0"),
    (r"localhost:\d+", "Hardcoded localhost address"),
]

# --- Color helpers ---

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color(text, code):
    return f"{code}{text}{RESET}"


# --- Git helpers ---

def get_staged_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True,
    )
    return [f for f in result.stdout.strip().split("\n") if f]


def get_staged_diff():
    result = subprocess.run(
        ["git", "diff", "--cached", "-U0"],
        capture_output=True, text=True,
    )
    return result.stdout


def get_staged_file_size(filepath):
    """Get the size of a staged file using git show."""
    result = subprocess.run(
        ["git", "cat-file", "-s", f":0:{filepath}"],
        capture_output=True, text=True,
    )
    try:
        return int(result.stdout.strip())
    except ValueError:
        return 0


# --- Checkers ---

def check_forbidden_files(staged_files):
    issues = []
    for filepath in staged_files:
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, filepath):
                issues.append((filepath, f"Forbidden file pattern: {pattern}"))
                break
    return issues


def check_large_files(staged_files):
    issues = []
    for filepath in staged_files:
        size = get_staged_file_size(filepath)
        if size > MAX_FILE_SIZE_BYTES:
            mb = size / (1024 * 1024)
            issues.append((filepath, f"Large file: {mb:.1f} MB (limit: {MAX_FILE_SIZE_BYTES // (1024*1024)} MB)"))
    return issues


def check_secrets(staged_files):
    issues = []
    for filepath in staged_files:
        result = subprocess.run(
            ["git", "show", f":{filepath}"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            continue
        content = result.stdout
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    snippet = line.strip()[:80]
                    issues.append((filepath, f"{label} (line {line_num}): {snippet}"))
    return issues


def check_code_quality(staged_files):
    warnings = []
    for filepath in staged_files:
        result = subprocess.run(
            ["git", "show", f":{filepath}"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            continue
        content = result.stdout
        ext = os.path.splitext(filepath)[1]
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, label in WARN_PATTERNS:
                # Skip console.log warning for JS-like files only checking non-Python debugger in Python, etc.
                if label == "console.log statement" and ext in (".py", ".rb", ".go", ".rs"):
                    continue
                if re.search(pattern, line):
                    snippet = line.strip()[:80]
                    warnings.append((filepath, f"{label} (line {line_num}): {snippet}"))
    return warnings


# --- Text-based checkers (for webhook / raw text input) ---

def scan_text_for_secrets(text, filename="<unknown>"):
    """Scan raw text for secret patterns. Returns list of (filename, description) tuples."""
    issues = []
    for line_num, line in enumerate(text.splitlines(), 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                snippet = line.strip()[:80]
                issues.append((filename, f"{label} (line {line_num}): {snippet}"))
    return issues


def scan_text_for_quality(text, filename="<unknown>"):
    """Scan raw text for quality warnings. Returns list of (filename, description) tuples."""
    warnings = []
    ext = os.path.splitext(filename)[1]
    for line_num, line in enumerate(text.splitlines(), 1):
        for pattern, label in WARN_PATTERNS:
            if label == "console.log statement" and ext in (".py", ".rb", ".go", ".rs"):
                continue
            if re.search(pattern, line):
                snippet = line.strip()[:80]
                warnings.append((filename, f"{label} (line {line_num}): {snippet}"))
    return warnings


def check_forbidden_filenames(filenames):
    """Check a list of filenames against forbidden patterns. Returns list of (filename, description) tuples."""
    issues = []
    for filepath in filenames:
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, filepath):
                issues.append((filepath, f"Forbidden file pattern: {pattern}"))
                break
    return issues


# --- Main ---

def main():
    staged_files = get_staged_files()
    if not staged_files:
        print(color("No staged files to review.", GREEN))
        sys.exit(0)

    print(color(f"\n{'='*60}", BOLD))
    print(color(" Pre-commit Review Agent", BOLD))
    print(color(f"{'='*60}", BOLD))
    print(f" Reviewing {len(staged_files)} staged file(s)...\n")

    blockers = []
    warnings = []

    # Forbidden files
    forbidden = check_forbidden_files(staged_files)
    for filepath, reason in forbidden:
        blockers.append((filepath, reason))

    # Large files
    large = check_large_files(staged_files)
    for filepath, reason in large:
        blockers.append((filepath, reason))

    # Secrets
    secrets = check_secrets(staged_files)
    for filepath, reason in secrets:
        blockers.append((filepath, reason))

    # Code quality
    quality = check_code_quality(staged_files)
    for filepath, reason in quality:
        warnings.append((filepath, reason))

    # --- Report ---
    has_blockers = len(blockers) > 0

    if blockers:
        print(color(f" BLOCK  ({len(blockers)} issue(s))", RED + BOLD))
        print(color(" " + "-" * 40, RED))
        for filepath, reason in blockers:
            print(f"  {color('x', RED)} {color(filepath, BOLD)}")
            print(f"    {reason}")
        print()

    if warnings:
        print(color(f" WARN  ({len(warnings)} issue(s))", YELLOW + BOLD))
        print(color(" " + "-" * 40, YELLOW))
        for filepath, reason in warnings:
            print(f"  {color('!', YELLOW)} {color(filepath, BOLD)}")
            print(f"    {reason}")
        print()

    if has_blockers:
        print(color(" Commit BLOCKED. Fix the issues above and try again.", RED + BOLD))
        print()
        sys.exit(1)
    elif warnings:
        print(color(" Commit allowed (with warnings).", YELLOW + BOLD))
        print()
        sys.exit(0)
    else:
        print(color(" All checks passed!", GREEN + BOLD))
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
