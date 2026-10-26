"""All credentials below are synthetic, assembled offline, and never usable."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import scanner

FAKE_TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
FAKE_PASSWORD = 'synthetic-only-password-938!'

class RulesTests(unittest.TestCase):
    def test_provider_patterns(self):
        cases = [('AKIA' + 'Z'*16, 'aws-access-key'),
                 (FAKE_TOKEN, 'github-token'),
                 ('xoxb-' + '12345abcde'*3, 'slack-token'),
                 ('AIza' + 'B'*35, 'google-api-key')]
        for value, rule in cases:
            with self.subTest(rule=rule):
                self.assertIn(rule, [f.rule for f in scanner.scan_text(value, 'a')])
    def test_private_keys(self):
        for prefix in ('', 'RSA ', 'EC ', 'OPENSSH ', 'ENCRYPTED '):
            self.assertEqual(scanner.scan_text('-----BEGIN '+prefix+'PRIVATE KEY-----', 'key')[0].rule, 'private-key')
    def test_assignment_and_line(self):
        result = scanner.scan_text('\npassword = "'+FAKE_PASSWORD+'"', 'settings.py')
        self.assertEqual((result[0].rule, result[0].line), ('secret-assignment', 2))
    def test_json_assignment(self):
        self.assertEqual(scanner.scan_text('{"api_key": "synthetic-test-key-123"}', 'x')[0].rule, 'secret-assignment')
    def test_placeholders(self):
        for value in ('changeme', 'password', '${API_KEY}', '<token>', 'YOUR_API_KEY'):
            self.assertEqual(scanner.scan_text('token = "'+value+'"', 'a'), [])
    def test_entropy(self):
        value = 'aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW'
        self.assertGreater(scanner.entropy(value), 4.3)
        self.assertEqual(scanner.scan_text(value, 'a')[0].rule, 'high-entropy-token')
        self.assertEqual(scanner.scan_text(value, 'a', use_entropy=False), [])
    def test_low_entropy_and_hex(self):
        self.assertEqual(scanner.scan_text('a'*40+'\n0123456789abcdef'*4, 'a'), [])
    def test_redaction(self):
        findings = scanner.scan_text('password = "'+FAKE_PASSWORD+'"', 'a')
        self.assertNotIn(FAKE_PASSWORD, json.dumps([scanner.asdict(f) for f in findings]))
    def test_binary(self):
        self.assertIsNone(scanner.decode(b'abc\0def'))
        self.assertIsNone(scanner.decode(b'\xff'))
    def test_fingerprint_stable(self):
        self.assertEqual(scanner.scan_text(FAKE_TOKEN, 'a')[0].fingerprint,
                         scanner.scan_text(FAKE_TOKEN, 'b')[0].fingerprint)

class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def write(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
    def test_worktree_and_exclusions(self):
        self.write('.env', 'password = "'+FAKE_PASSWORD+'"')
        self.write('node_modules/x.js', FAKE_TOKEN)
        self.write('ignore.txt', FAKE_TOKEN)
        report = scanner.scan_repo(self.root, history=False, excludes=['ignore.txt'])
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['path'], '.env')
    def test_symlink_and_size(self):
        self.write('big.txt', FAKE_TOKEN)
        (self.root/'link').symlink_to(self.root/'big.txt')
        report = scanner.scan_repo(self.root, history=False, max_bytes=10)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['stats']['skipped_files'], 2)
    def test_non_repo_error(self):
        with self.assertRaises(ValueError):
            scanner.scan_repo(self.root)
    def test_missing_directory(self):
        with self.assertRaises(ValueError):
            scanner.scan_repo(self.root/'missing')
    def test_cli_json_and_exit(self):
        self.write('.env', 'password = "'+FAKE_PASSWORD+'"')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = scanner.main([str(self.root), '--no-history', '--format', 'json'])
        self.assertEqual(code, 1)
        self.assertEqual(len(json.loads(output.getvalue())['findings']), 1)
        self.assertNotIn(FAKE_PASSWORD, output.getvalue())
    def test_clean_exit(self):
        self.write('hello.py', 'print("hello")')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([str(self.root), '--no-history']), 0)
    @unittest.skipUnless(shutil.which('git'), 'Git required')
    def test_deleted_history_and_other_branch(self):
        def git(*args):
            subprocess.run(['git', '-C', str(self.root), *args], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        git('init', '-b', 'main')
        git('config', 'user.email', 'fixture@example.invalid')
        git('config', 'user.name', 'Test Fixture')
        self.write('deleted.env', 'password = "'+FAKE_PASSWORD+'"')
        git('add', '.')
        git('commit', '-m', 'Plant synthetic fixture')
        git('checkout', '-b', 'side')
        self.write('side.txt', FAKE_TOKEN)
        git('add', '.')
        git('commit', '-m', 'Add fake token on side branch')
        git('checkout', 'main')
        git('rm', 'deleted.env')
        git('commit', '-m', 'Remove fixture from working tree')
        report = scanner.scan_repo(self.root, max_commits=0)
        self.assertEqual({f['path'] for f in report['findings']}, {'deleted.env', 'side.txt'})
        self.assertTrue(all(f['source'] == 'history' for f in report['findings']))
        self.assertEqual(report['stats']['commits'], 3)
        self.assertEqual(report['stats']['history_blobs'], 2)
        limited = scanner.scan_repo(self.root, max_commits=1)
        self.assertTrue(limited['notices'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([str(self.root), '--max-commits', '1']), 2)

class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'.env').write_text('password = "'+FAKE_PASSWORD+'"')
        self.finding = scanner.scan_repo(self.root, history=False)['findings'][0]
        self.allowlist = self.root/'allowlist.json'
    def write_allowlist(self, **changes):
        row = {key: self.finding[key] for key in ('source', 'path', 'rule', 'fingerprint', 'line')}
        row.update(changes)
        self.allowlist.write_text(json.dumps({'version': 1, 'allow': [row]}))
        return row
    def test_exact_reviewed_match_is_suppressed(self):
        self.write_allowlist(reason='Reviewed synthetic fixture')
        allowlist = scanner.load_allowlist(self.allowlist)
        report = scanner.scan_repo(self.root, history=False, allowlist=allowlist)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['stats']['allowlist_entries'], 1)
        self.assertEqual(report['stats']['suppressed_findings'], 1)
        self.assertEqual(report['stats']['unused_allowlist_entries'], 0)
    def test_line_mismatch_does_not_suppress(self):
        self.write_allowlist(line=self.finding['line'] + 1)
        allowlist = scanner.load_allowlist(self.allowlist)
        report = scanner.scan_repo(self.root, history=False, allowlist=allowlist)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['stats']['suppressed_findings'], 0)
        self.assertEqual(report['stats']['unused_allowlist_entries'], 1)
    def test_invalid_allowlist_entries_are_rejected(self):
        valid = {key: self.finding[key] for key in ('source', 'path', 'rule', 'fingerprint', 'line')}
        invalid_rows = [
            dict(valid, source='index'),
            dict(valid, path='../outside.env'),
            dict(valid, fingerprint='A' * 16),
            dict(valid, line=0),
            dict(valid, unknown='broad'),
        ]
        for row in invalid_rows:
            with self.subTest(row=row):
                self.allowlist.write_text(json.dumps({'version': 1, 'allow': [row]}))
                with self.assertRaises(ValueError):
                    scanner.load_allowlist(self.allowlist)
    def test_invalid_document_and_limits(self):
        for text in ('not json', '{"version":2,"allow":[]}', '{"version":1,"allow":{}}'):
            self.allowlist.write_text(text)
            with self.assertRaises(ValueError):
                scanner.load_allowlist(self.allowlist)
    def test_cli_allowlist_exit_and_redaction(self):
        self.write_allowlist(reason='Reviewed synthetic fixture')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = scanner.main([str(self.root), '--no-history', '--allowlist', str(self.allowlist)])
        self.assertEqual(code, 0)
        self.assertIn('Suppressed by reviewed allowlist: 1', output.getvalue())
        self.assertNotIn(FAKE_PASSWORD, output.getvalue())
    def test_cli_bad_allowlist_fails_closed(self):
        self.allowlist.write_text('{"version":1,"allow":[{"path":".env"}]}')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main([str(self.root), '--no-history', '--allowlist', str(self.allowlist)]), 2)


if __name__ == '__main__':
    unittest.main()
