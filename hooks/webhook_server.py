#!/usr/bin/env python3
"""GitHub webhook server: reviews pull requests for secrets and code quality."""

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys

from flask import Flask, abort, jsonify, request

from review_agent import (
    FORBIDDEN_PATTERNS,
    SECRET_PATTERNS,
    WARN_PATTERNS,
    check_forbidden_filenames,
    scan_text_for_quality,
    scan_text_for_secrets,
)

app = Flask(__name__)

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

# --- Color helpers (for terminal output) ---
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color(text, code):
    return f"{code}{text}{RESET}"


# --- Signature verification ---

def verify_signature(payload_body, signature_header):
    """Verify the GitHub webhook HMAC SHA-256 signature."""
    if not WEBHOOK_SECRET:
        print(color("  WARNING: WEBHOOK_SECRET not set, skipping signature verification", YELLOW))
        return True
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# --- Diff parsing ---

def parse_diff(diff_text):
    """Parse unified diff, extracting added lines per file.

    Returns dict: {filename: text_of_added_lines}
    """
    files = {}
    current_file = None
    added_lines = []

    for line in diff_text.splitlines():
        # Detect file header: +++ b/path/to/file
        if line.startswith("+++ b/"):
            # Save previous file
            if current_file and added_lines:
                files[current_file] = "\n".join(added_lines)
            current_file = line[6:]  # strip "+++ b/"
            added_lines = []
        elif line.startswith("+") and not line.startswith("+++"):
            # Added line (strip the leading "+")
            added_lines.append(line[1:])

    # Save last file
    if current_file and added_lines:
        files[current_file] = "\n".join(added_lines)

    return files


# --- PR review logic ---

def review_pr(pr_number, repo):
    """Fetch the PR diff, run checks, and post a review."""
    print(color(f"\n{'='*60}", BOLD))
    print(color(f"  Reviewing PR #{pr_number} on {repo}", BOLD))
    print(color(f"{'='*60}", BOLD))

    # Fetch diff
    result = subprocess.run(
        ["gh", "pr", "diff", str(pr_number), "--repo", repo],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(color(f"  ERROR: Failed to fetch diff: {result.stderr}", RED))
        return

    diff_text = result.stdout
    if not diff_text.strip():
        print("  No diff content found.")
        return

    file_additions = parse_diff(diff_text)
    filenames = list(file_additions.keys())

    print(f"  Files changed: {len(filenames)}")
    for f in filenames:
        print(f"    - {f}")

    blockers = []
    warnings = []

    # Check forbidden filenames
    blockers.extend(check_forbidden_filenames(filenames))

    # Scan each file's added lines
    for filename, text in file_additions.items():
        blockers.extend(scan_text_for_secrets(text, filename))
        warnings.extend(scan_text_for_quality(text, filename))

    # --- Log findings ---
    if blockers:
        print(color(f"\n  BLOCKERS ({len(blockers)}):", RED + BOLD))
        for filepath, reason in blockers:
            print(f"    {color('x', RED)} {filepath}: {reason}")

    if warnings:
        print(color(f"\n  WARNINGS ({len(warnings)}):", YELLOW + BOLD))
        for filepath, reason in warnings:
            print(f"    {color('!', YELLOW)} {filepath}: {reason}")

    if not blockers and not warnings:
        print(color("\n  All checks passed!", GREEN + BOLD))

    # --- Build review body ---
    body_lines = ["## Automated Review Agent\n"]

    if blockers:
        body_lines.append("### Blockers\n")
        for filepath, reason in blockers:
            body_lines.append(f"- **{filepath}**: {reason}")
        body_lines.append("")

    if warnings:
        body_lines.append("### Warnings\n")
        for filepath, reason in warnings:
            body_lines.append(f"- **{filepath}**: {reason}")
        body_lines.append("")

    if not blockers and not warnings:
        body_lines.append("All checks passed. No secrets, forbidden files, or quality issues detected.\n")

    body = "\n".join(body_lines)

    # --- Post review ---
    if blockers:
        review_event = "REQUEST_CHANGES"
    elif warnings:
        review_event = "COMMENT"
    else:
        review_event = "APPROVE"

    print(f"\n  Posting review: {review_event}")

    result = subprocess.run(
        ["gh", "pr", "review", str(pr_number), "--repo", repo,
         f"--{review_event.lower().replace('_', '-')}", "--body", body],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(color(f"  ERROR posting review: {result.stderr}", RED))
    else:
        print(color("  Review posted successfully.", GREEN))


# --- Routes ---

@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(request.data, signature):
        abort(403, "Invalid signature")

    event = request.headers.get("X-GitHub-Event", "")

    if event == "ping":
        print(color("  Received ping event", GREEN))
        return jsonify({"msg": "pong"}), 200

    if event != "pull_request":
        return jsonify({"msg": f"Ignored event: {event}"}), 200

    payload = request.json
    action = payload.get("action", "")

    if action not in ("opened", "synchronize", "reopened"):
        print(f"  Ignored PR action: {action}")
        return jsonify({"msg": f"Ignored action: {action}"}), 200

    pr_number = payload["pull_request"]["number"]
    repo = payload["repository"]["full_name"]

    print(color(f"\n  PR event: #{pr_number} ({action}) on {repo}", BOLD))

    review_pr(pr_number, repo)

    return jsonify({"msg": "Review complete"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    if not WEBHOOK_SECRET:
        print(color("WARNING: WEBHOOK_SECRET env var not set. Signature verification disabled.", YELLOW))
    print(color(f"Starting webhook server on port 5000...", GREEN + BOLD))
    app.run(host="0.0.0.0", port=5000)
