"""Synthetic fixtures exercise index-only checks in temporary repositories."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import precommit
from test_scanner import FAKE_TOKEN


@unittest.skipUnless(shutil.which('git'), 'Git required')
class StagedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-b', 'main')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Synthetic Fixture')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stage(self, name, text):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        self.git('add', '--', name)
        return file

    def scan(self, **kwargs):
        return precommit.scan_staged(self.root, use_entropy=False, **kwargs)

    def test_staged_secret_survives_worktree_cleanup(self):
        file = self.stage('settings.txt', FAKE_TOKEN)
        file.write_text('safe unstaged replacement')
        report = self.scan()
        self.assertEqual(report['findings'][0]['source'], 'index')
        self.assertEqual(report['findings'][0]['rule'], 'github-token')
        self.assertNotIn(FAKE_TOKEN, json.dumps(report))

    def test_unstaged_secret_does_not_block_clean_index(self):
        file = self.stage('settings.txt', 'safe staged text')
        file.write_text(FAKE_TOKEN)
        self.assertEqual(self.scan()['findings'], [])

    def test_untracked_secret_ignored(self):
        (self.root / '.env').write_text(FAKE_TOKEN)
        self.assertEqual(self.scan()['stats']['staged_files'], 0)

    def test_unusual_filename(self):
        name = 'space tab\tnewline\nfile.txt'
        self.stage(name, FAKE_TOKEN)
        self.assertEqual(self.scan()['findings'][0]['path'], name)

    def test_renamed_blob(self):
        self.stage('old.txt', FAKE_TOKEN)
        self.git('commit', '-m', 'Synthetic fixture')
        self.git('mv', 'old.txt', 'new.txt')
        self.assertEqual(self.scan()['findings'][0]['path'], 'new.txt')

    def test_deleted_secret_ignored(self):
        self.stage('old.txt', FAKE_TOKEN)
        self.git('commit', '-m', 'Synthetic fixture')
        self.git('rm', 'old.txt')
        self.assertEqual(self.scan()['findings'], [])

    def test_subdirectory_invocation(self):
        self.stage('nested/file.txt', FAKE_TOKEN)
        self.assertEqual(precommit.scan_staged(self.root/'nested', use_entropy=False)['findings'][0]['path'], 'nested/file.txt')

    def test_excluded_and_binary_files(self):
        self.stage('node_modules/file.txt', FAKE_TOKEN)
        file = self.stage('binary.dat', 'temporary')
        file.write_bytes(b'\0' + FAKE_TOKEN.encode())
        self.git('add', 'binary.dat')
        report = self.scan()
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['stats']['skipped_files'], 2)

    def test_oversize_is_incomplete(self):
        self.stage('large.txt', FAKE_TOKEN)
        self.assertTrue(self.scan(max_bytes=10)['notices'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(precommit.main([str(self.root), '--max-bytes', '10']), 2)

    def test_json_exit_codes_and_redaction(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(precommit.main([str(self.root)]), 0)
        self.stage('secret.txt', FAKE_TOKEN)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(precommit.main([str(self.root), '--format', 'json']), 1)
        self.assertNotIn(FAKE_TOKEN, out.getvalue())
        self.assertTrue(json.loads(out.getvalue())['findings'])

    def test_invalid_limit_and_non_repository(self):
        with self.assertRaises(ValueError):
            self.scan(max_bytes=0)
        other = self.root/'not-a-repo'
        other.mkdir()
        # A directory inside a repository is valid, but a missing target is not.
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(precommit.main([str(self.root/'missing')]), 2)

    @unittest.skipUnless(hasattr(Path, 'symlink_to'), 'Symlinks required')
    def test_symlink_not_followed(self):
        self.stage('target.txt', 'safe')
        try:
            (self.root/'link').symlink_to('target.txt')
        except OSError:
            self.skipTest('Symlinks unavailable on this system')
        self.git('add', 'link')
        self.assertEqual(self.scan()['stats']['skipped_files'], 1)

    def test_unmerged_index_fails_closed(self):
        self.stage('conflict.txt', 'base')
        self.git('commit', '-m', 'Base fixture')
        self.git('checkout', '-b', 'side')
        self.stage('conflict.txt', 'side')
        self.git('commit', '-m', 'Side fixture')
        self.git('checkout', 'main')
        self.stage('conflict.txt', 'main')
        self.git('commit', '-m', 'Main fixture')
        result = subprocess.run(['git', '-C', str(self.root), 'merge', 'side'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.scan()['notices'])


if __name__ == '__main__':
    unittest.main()
