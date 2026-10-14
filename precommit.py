#!/usr/bin/env python3
"""Check staged Git blobs, never unstaged working-tree content."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

import scanner


def scan_staged(root='.', use_entropy=True, max_bytes=1024 * 1024):
    root = Path(root).resolve()
    if max_bytes <= 0:
        raise ValueError('max-bytes must be positive')
    # Resolve the actual root so invocation in a subdirectory is safe.
    root = Path(scanner.git(root, 'rev-parse', '--show-toplevel').decode().strip())
    names = scanner.git(root, 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z')
    entries = scanner.git(root, 'ls-files', '--stage', '-z')
    index = {}
    for entry in entries.split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, oid, stage = header.decode().split()
        if stage == '0':
            index[name] = (mode, oid)
    findings, notices = [], []
    stats = {'staged_files': 0, 'skipped_files': 0}
    for name in names.split(b'\0'):
        if not name:
            continue
        path = name.decode('utf-8', errors='replace')
        if name not in index:
            notices.append('Staged entry unavailable: ' + path)
            continue
        mode, oid = index[name]
        if mode not in ('100644', '100755') or scanner.excluded(path, scanner.DEFAULT_EXCLUDES):
            stats['skipped_files'] += 1
            continue
        if int(scanner.git(root, 'cat-file', '-s', oid)) > max_bytes:
            notices.append('Staged file exceeds max-bytes: ' + path)
            stats['skipped_files'] += 1
            continue
        text = scanner.decode(scanner.git(root, 'cat-file', 'blob', oid))
        if text is None:
            stats['skipped_files'] += 1
            continue
        stats['staged_files'] += 1
        findings.extend(asdict(f) for f in scanner.scan_text(text, path, 'index', use_entropy=use_entropy))
    # A conflicted index is not a clean check even when diff-filter omits U.
    if scanner.git(root, 'ls-files', '--unmerged', '-z'):
        notices.append('Unmerged index entries must be resolved before checking')
    return {'findings': findings, 'stats': stats, 'notices': notices,
            'scope': 'Added, copied, modified and renamed staged files only; no worktree or history scan'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', nargs='?', default='.')
    parser.add_argument('--no-entropy', action='store_true')
    parser.add_argument('--max-bytes', type=int, default=1024 * 1024)
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    options = parser.parse_args(argv)
    try:
        report = scan_staged(options.path, not options.no_entropy, options.max_bytes)
    except (ValueError, OSError, RuntimeError) as error:
        print('Error: ' + str(error), file=sys.stderr)
        return 2
    if options.format == 'json':
        print(json.dumps(report, indent=2))
    else:
        print('Staged Secret Scanner: %d finding(s)' % len(report['findings']))
        for finding in report['findings']:
            print('{path}:{line} {rule} [{severity}] {redacted}'.format(**finding))
        for notice in report['notices']:
            print('NOTICE:', notice)
    return 2 if report['notices'] else (1 if report['findings'] else 0)


if __name__ == '__main__':
    sys.exit(main())
