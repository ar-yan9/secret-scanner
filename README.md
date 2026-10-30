# Secret Scanner

A dependency-free Python CLI that finds possible leaked credentials in local files and reachable Git history. It supports SOC 2 confidentiality controls by helping a team detect accidental credential exposure. It does **not** certify SOC 2 compliance, replace an audit, verify whether credentials work, or prove a repository is secure.

## Run

Requires Python 3.10+ and Git for history scanning. No paid services, network requests, or external Python packages.

```bash
git clone https://github.com/ar-yan9/secret-scanner.git
cd secret-scanner
python3 scanner.py /path/to/repository
python3 scanner.py /path/to/repository --format json > report.json
python3 scanner.py /path/to/repository --format sarif > report.sarif
python3 scanner.py /path/to/repository --max-commits 0
python3 scanner.py /path/to/folder --no-history --exclude 'fixtures/*'
python3 scanner.py /path/to/repository --allowlist reviewed-allowlist.json
python3 -m unittest -v
```

On Windows, use `py -3.11` instead of `python3` if that is your Python launcher. Quote glob arguments so your shell does not expand them.

Exit codes: **0** = no active findings in the scanned scope; **1** = possible secrets found; **2** = error or incomplete scan (including a history limit or unreadable file). Reviewed allowlist matches are suppressed from active findings and counted separately. JSON output includes findings, scan counts, allowlist counts, notices and scope. SARIF output keeps the same active findings in SARIF 2.1.0 form for tools that consume SARIF; it remains redacted and this repository's CI does not upload it anywhere.

## Staged check and optional pre-commit hook

```bash
python3 precommit.py
python3 precommit.py --format json
python3 precommit.py --no-entropy
```

The staged check reads Git's **index blobs**, not files on disk. Cleaning a secret
in your editor without staging the fix does not hide a staged secret. Untracked,
unstaged and deleted files are outside this check; use `scanner.py` for local
files and history. Added, modified, copied and renamed paths are checked, including
filenames containing spaces, tabs or newlines. Unmerged index entries and oversized
staged files return exit 2. Binary files, symlinks, submodules and the scanner's
default excluded directories are skipped. All reports remain redacted.

This repository includes an optional `.pre-commit-config.yaml` for the
[pre-commit framework](https://pre-commit.com/). With that framework already
installed and `python3` on PATH, run `pre-commit install` from this repository.
On Windows, change the config's entry to `py -3 precommit.py` if needed.
The framework is optional: the standalone staged check uses only Python and Git.
Review an existing hook before installing; do not overwrite another team's hook.

To use it in another repository, copy `scanner.py` and `precommit.py` there, then
merge the local hook entry into that repository's config. This is a local hook,
not a remotely installable package. A hook can be bypassed and only covers its
stated scope; it is not a security guarantee or a replacement for CI/review.

## What v1 checks

- AWS access-key IDs, GitHub tokens, Slack tokens and Google API-key shapes.
- PEM/OpenSSH private-key headers, including encrypted private-key headers.
- Quoted assignments to common password, token, API-key and secret names. Obvious placeholders are filtered.
- Mixed letter/digit strings with Shannon entropy of at least 4.3 bits per character, 24-128 characters long. These are low-confidence candidates, not confirmed credentials. Hex-only strings are skipped by the entropy rule because hashes are common.
- Files on disk, including untracked and hidden files such as `.env`.
- Every distinct path/blob pair in commit trees reachable from **local** refs, including deleted files and other local branches. A finding records one representative commit containing the blob, not necessarily its first introduction.

Reports include rule, severity, file, line, source, commit and a truncated SHA-256 fingerprint. Matching values and source lines are never printed. SARIF results use severity mapping high→error, medium→warning and low→note, with the fingerprint in `partialFingerprints` and the representative commit in result properties when present. The fingerprint allows repeated-value comparison; it is **not anonymization** for guessable passwords. Paths, commit IDs and fingerprints may still be sensitive. Keep reports private.

## Reviewed allowlist

Use an allowlist only for a finding a person has reviewed and confirmed is not a real exposure, such as a documented synthetic fixture. It is not a broad ignore file and does not store the secret value. Every entry must match the finding's source, root-relative path, rule, 16-character fingerprint and original line exactly:

```json
{
  "version": 1,
  "allow": [
    {
      "source": "worktree",
      "path": "tests/fixtures/example.py",
      "rule": "high-entropy-token",
      "fingerprint": "0123456789abcdef",
      "line": 3,
      "reason": "Documented synthetic fixture"
    }
  ]
}
```

Unknown fields, broad patterns, absolute paths, parent-directory paths and invalid fingerprints are rejected. The file is capped at 64 KiB and 1,000 entries. If a matched finding moves to another line or changes value, it becomes active again. Scan stats show `allowlist_entries`, `suppressed_findings` and `unused_allowlist_entries`, so stale entries remain visible. The allowlist applies to `scanner.py` worktree/history scans only; the staged `precommit.py` check intentionally has no suppression path.

## Scope and limits

Default history limit: 200 commits. A notice and exit 2 mean coverage was incomplete. Use `--max-commits 0` for all reachable local history. No remote refs are fetched, and shallow clones, dangling objects, reflogs, LFS contents and submodule contents are not covered. History scanning must start at the Git repository root.

Files larger than 1 MiB, non-UTF-8/binary files and symlinks are skipped. Default excluded directories: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`. Counts show skipped files, but a clean result does not cover these exclusions. Customize with repeatable root-relative `--exclude` globs and `--max-bytes`. Exclusion applies to both disk and history. Suppression applies only after a full scan and only to exact reviewed findings.

False positives and false negatives are expected. Rules do not cover every provider, encoding, secret format, unquoted assignment or multi-line value. The tool never contacts a provider to validate a key. Only scan repositories you own or are authorized to inspect. It does not change files or Git history.

Tests include a Windows-safe unusual filename on every platform. The tab/newline filename fixture runs on POSIX and is skipped on Windows, where those names cannot be created. CI checks both Ubuntu and Windows.

For a planted-fixture demo, run the tests: they create a temporary Git repository, commit synthetic secrets, delete them, and leave another fake token on a side branch. No real credentials are used. Scanning this project's test code may produce deliberate test-data findings.

## SOC 2 connection

[AICPA describes SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2/) as an examination of a service organization's controls relevant to security, availability, processing integrity, confidentiality or privacy. This project is a small engineering aid, not an examination.

| Practice | How this tool helps | What people still need to do |
| --- | --- | --- |
| Identify exposure of confidential credentials | Detect likely secrets in code and historical blobs | Classify data, review alerts, determine actual exposure |
| Limit unauthorized access | Highlight tokens and private keys for investigation | Revoke/rotate exposed credentials and review access logs |
| Monitor a secure development process | Produce redacted machine-readable evidence for checks | Set review ownership, policies, retention and alert handling |

Do not label a scan score as "SOC 2 compliant". There is no compliance score here.

## If a secret is found

1. Review locally without sharing the value or report publicly.
2. Revoke/rotate any real credential promptly at its issuer. Deleting a file alone does not revoke a key.
3. Check access and audit logs; notify the relevant owner through your incident process.
4. Remove the value and prevent recurrence. Coordinate history rewriting separately with collaborators, if necessary.
5. Re-scan and document the response securely.

## Next work

Add baseline generation, richer provider rules, and a configurable CI check. The staged check and optional local pre-commit hook are available now. Keep benchmarks and claims based on real tests.
