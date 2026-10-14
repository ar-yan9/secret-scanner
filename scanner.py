#!/usr/bin/env python3
"""Offline, redacted secret detection for local files and reachable Git history."""
import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import fnmatch
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys

RULES = [
    ('aws-access-key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'), 'high'),
    ('github-token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b'), 'high'),
    ('slack-token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,255}\b'), 'high'),
    ('google-api-key', re.compile(r'\bAIza[A-Za-z0-9_-]{35}\b'), 'high'),
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'), 'high'),
]
ASSIGNMENT = re.compile(
    r'''(?ix)["']?\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,512})["']''')
ENTROPY_TOKEN = re.compile(r'(?<![\w/])[A-Za-z0-9+/=_-]{24,128}(?![\w/])')
PLACEHOLDER = re.compile(r'(?i)^(?:changeme|password|example|placeholder|your[_-].*|<.*>|\$\{.*\}|\{\{.*\}\})$')
DEFAULT_EXCLUDES = ('node_modules/*', '.venv/*', 'venv/*', '__pycache__/*', '.git/*')

@dataclass(frozen=True)
class Finding:
    source: str
    path: str
    line: int
    rule: str
    severity: str
    fingerprint: str
    commit: str = ''
    redacted: str = '[REDACTED]'


def entropy(value):
    if not value:
        return 0.0
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())


def scan_text(text, path, source='worktree', commit='', use_entropy=True):
    """Never return the matching value or original line."""
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        candidates = []
        for name, pattern, severity in RULES:
            candidates.extend((m.start(), m.end(), name, severity, m.group()) for m in pattern.finditer(line))
        for match in ASSIGNMENT.finditer(line):
            value = match.group(1)
            if not PLACEHOLDER.fullmatch(value):
                candidates.append((match.start(1), match.end(1), 'secret-assignment', 'medium', value))
        if use_entropy:
            covered = [(a, b) for a, b, *_ in candidates]
            for match in ENTROPY_TOKEN.finditer(line):
                value = match.group()
                # Hex strings are often hashes; entropy alone cannot identify a secret.
                if (not re.fullmatch(r'[a-fA-F0-9]+', value) and entropy(value) >= 4.3
                        and any(c.isalpha() for c in value) and any(c.isdigit() for c in value)
                        and not any(match.start() < b and match.end() > a for a, b in covered)):
                    candidates.append((match.start(), match.end(), 'high-entropy-token', 'low', value))
        seen = set()
        for _, _, rule, severity, value in candidates:
            digest = hashlib.sha256(value.encode()).hexdigest()[:16]
            if (rule, digest) not in seen:
                seen.add((rule, digest))
                findings.append(Finding(source, path, number, rule, severity, digest, commit))
    return findings


def excluded(path, patterns):
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def decode(data):
    if b'\0' in data:
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return None


def git(root, *args):
    try:
        result = subprocess.run(['git', '-C', str(root), *args], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('Git unavailable or timed out') from error
    if result.returncode:
        # Do not echo Git stderr: it can include sensitive repository data.
        raise RuntimeError('Git command failed: ' + args[0])
    return result.stdout


def scan_repo(root, history=True, use_entropy=True, max_bytes=1024*1024,
              max_commits=200, excludes=()):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError('Scan target must be a directory')
    patterns = DEFAULT_EXCLUDES + tuple(excludes)
    findings, notices = [], []
    stats = {'worktree_files': 0, 'history_blobs': 0, 'commits': 0, 'skipped_files': 0}
    # Iterative traversal, pruning defaults and never following symlinks.
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir())
        except OSError:
            notices.append('Could not read a directory: ' + str(directory.relative_to(root)))
            continue
        for item in children:
            relative = item.relative_to(root).as_posix()
            if item.name == '.git' or item.is_symlink() or excluded(relative, patterns):
                stats['skipped_files'] += 1
                continue
            if item.is_dir():
                if excluded(relative + '/', patterns):
                    stats['skipped_files'] += 1
                else:
                    pending.append(item)
                continue
            if not item.is_file():
                stats['skipped_files'] += 1
                continue
            try:
                with item.open('rb') as handle:
                    data = handle.read(max_bytes + 1)
            except OSError:
                notices.append('Could not read file: ' + relative)
                continue
            text = decode(data) if len(data) <= max_bytes else None
            if text is None:
                stats['skipped_files'] += 1
                continue
            stats['worktree_files'] += 1
            findings.extend(scan_text(text, relative, use_entropy=use_entropy))
    if history:
        # Scan every distinct path/blob pair reachable from local refs, not only HEAD.
        try:
            top = Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
            if top != root:
                raise ValueError('History scanning requires the repository root')
            args = ['rev-list', '--all']
            if max_commits:
                args.append('--max-count=' + str(max_commits + 1))
            commits = git(root, *args).decode().splitlines()
            if max_commits and len(commits) > max_commits:
                notices.append('History truncated at %d commits; use --max-commits 0 for all reachable history' % max_commits)
                commits = commits[:max_commits]
            seen = set()
            for commit in commits:
                stats['commits'] += 1
                entries = git(root, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0')
                for entry in entries:
                    if not entry:
                        continue
                    header, path_bytes = entry.split(b'\t', 1)
                    mode, kind, oid = header.decode().split()
                    path = path_bytes.decode('utf-8', errors='replace')
                    if kind != 'blob' or mode == '120000' or excluded(path, patterns):
                        continue
                    key = (oid, path)
                    if key in seen:
                        continue
                    seen.add(key)
                    if int(git(root, 'cat-file', '-s', oid)) > max_bytes:
                        stats['skipped_files'] += 1
                        continue
                    text = decode(git(root, 'cat-file', 'blob', oid))
                    if text is None:
                        stats['skipped_files'] += 1
                        continue
                    stats['history_blobs'] += 1
                    findings.extend(scan_text(text, path, 'history', commit, use_entropy))
        except RuntimeError as error:
            raise ValueError('History scan unavailable. Check Git installation/repository, or use --no-history') from error
    findings.sort(key=lambda f: (f.source, f.path, f.commit, f.line, f.rule))
    return {'findings': [asdict(f) for f in findings], 'stats': stats, 'notices': notices,
            'scope': 'Local files and reachable local Git refs only; no remote fetch'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', nargs='?', default='.')
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    parser.add_argument('--no-history', action='store_true')
    parser.add_argument('--no-entropy', action='store_true')
    parser.add_argument('--exclude', action='append', default=[], help='Root-relative glob; repeatable')
    parser.add_argument('--max-bytes', type=int, default=1024*1024)
    parser.add_argument('--max-commits', type=int, default=200, help='0 means all reachable commits')
    options = parser.parse_args(argv)
    if options.max_bytes <= 0 or options.max_commits < 0:
        parser.error('max-bytes must be positive and max-commits nonnegative')
    try:
        report = scan_repo(options.path, not options.no_history, not options.no_entropy,
                           options.max_bytes, options.max_commits, options.exclude)
    except (ValueError, OSError) as error:
        print('Error: ' + str(error), file=sys.stderr)
        return 2
    if options.format == 'json':
        print(json.dumps(report, indent=2))
    else:
        print('Secret Scanner: %d finding(s)' % len(report['findings']))
        for finding in report['findings']:
            print('{source} {path}:{line} {rule} [{severity}] {redacted} fingerprint={fingerprint} commit={commit}'.format(**finding))
        print('Scanned:', report['stats'])
        for notice in report['notices']:
            print('NOTICE:', notice)
    # An incomplete scan must never be mistaken for a clean pass.
    return 2 if report['notices'] else (1 if report['findings'] else 0)

if __name__ == '__main__':
    sys.exit(main())
