import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from plugin_claim_audit.cli import audit, doc_claims, main, PLUGIN, NOPLUGIN

ROOT = Path(__file__).resolve().parents[1]
GOOD = [
    'import importlib.metadata as md\neps = md.entry_points()\nfor ep in eps: ep.load()',
    'import pluggy as pg\npm = pg.PluginManager("x")\npm.register(object())',
    'from stevedore import ExtensionManager\nExtensionManager("x")',
    'import os as o\nfrom importlib import import_module as load\nfor name in o.listdir("plugins/"): load(name)',
    'import importlib\nPLUGINS[name] = importlib.import_module("fixed")',
]


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(ROOT / 'tests'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
        return target

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.root)] + list(args))
        return code, out.getvalue(), err.getvalue()

    def test_01_each_evidence_kind(self):
        self.write('README.md', 'supports plugins')
        for source in GOOD:
            with self.subTest(source=source):
                self.write('loader.py', source)
                self.assertEqual(self.cli()[0], 0)
                self.assertTrue(audit(self.root)['evidence'])

    def test_02_false_positive_claim(self):
        self.write('README.md', 'plugin support')
        self.write('app.py', 'x = 1')
        code, out, _ = self.cli('--json')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['findings'], [{'rule': 'documented-plugin-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])

    def test_03_false_negative_claim(self):
        self.write('README.md', 'no plugins')
        self.write('loader.py', GOOD[0])
        code, out, _ = self.cli('--json')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['findings'], [{'rule': 'documented-no-plugin-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])

    def test_04_no_source_asymmetry(self):
        self.write('README.md', 'supports plugins')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'HIGH')
        self.write('README.md', 'no plugins')
        self.assertEqual(self.cli()[0], 0)

    def test_05_fenced_inline_wrapped(self):
        for content in ['```text\nplugin support\n```', '~~~\nplugin support\n~~~']:
            self.write('README.md', content)
            self.assertEqual(audit(self.root)['claims'], [])
        for content in ['`plugin support`', 'plugin\nsupport', 'PLUGIN-SUPPORT']:
            self.write('README.md', content)
            self.assertEqual(self.cli()[0], 2)
        self.write('README.md', 'plugin\n\nsupport')
        self.assertEqual(self.cli()[0], 0)

    def test_06_span_removal(self):
        for phrase in ['does not support plugins', 'no plugin support']:
            self.assertEqual(doc_claims(phrase), {'NOPLUGIN'})
            self.write('README.md', phrase)
            self.assertEqual(self.cli()[0], 0)
            self.write('loader.py', GOOD[0])
            self.assertEqual([f['rule'] for f in audit(self.root)['findings']], ['documented-no-plugin-claim-false'])
            (self.root / 'loader.py').unlink()

    def test_07_bare_nouns_and_boundaries(self):
        for text in ['the plugin handles requests', 'extensions are welcome', 'plugins extension extensible pluggable', 'plugin models', 'supports pluginsXYZ']:
            self.assertEqual(doc_claims(text), set())

    def test_08_not_evidence(self):
        variants = [
            'import pluggy',
            'from importlib.metadata import entry_points\nentry_points()',
            'ep.load()',
            'import importlib\nimportlib.import_module("fixed")',
            'import os, importlib\nos.listdir("modules")\nimportlib.import_module(name)',
            'plugins = {}',
            'class PluginBase: pass',
            'import stevedore',
            'import importlib.metadata',
            '# ep.load()\nx = "importlib.metadata.entry_points()"',
            'def plugin_loader(): pass',
            'self.plugins = []\nimport importlib\nimportlib.import_module("fixed")',
        ]
        self.write('README.md', 'plugin support')
        for source in variants:
            with self.subTest(source=source):
                self.write('app.py', source)
                self.assertFalse(audit(self.root)['evidence'])
                self.assertEqual(self.cli()[0], 2)

    def test_08_entry_disjointness(self):
        self.write('README.md', 'plugin support')
        self.write('pyproject.toml', '[project.scripts]\napp = "app:main"\n[project.entry-points."host.plugins"]\napp = "app:main"\n')
        self.assertEqual(self.cli()[0], 2)
        self.assertEqual(audit(self.root)['evidence'], [])

    def test_08_pairing_cannot_cross_modules(self):
        self.write('README.md', 'plugin support')
        self.write('discover.py', 'from importlib.metadata import entry_points\nentry_points()')
        self.write('load.py', 'ep.load()')
        self.assertEqual(self.cli()[0], 2)

    def test_09_medium_threshold(self):
        self.write('tests/docs/guide.md', 'plugin support')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'MEDIUM')
        self.assertEqual(self.cli()[0], 2)
        code, out, _ = self.cli('--fail-on', 'HIGH', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)['findings']), 1)

    def test_10_family_dedup_prefers_high(self):
        self.write('tests/docs/guide.md', 'plugin support')
        self.write('docs/z.md', 'plugin support')
        self.write('docs/a.md', 'supports plugins')
        findings = audit(self.root)['findings']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['path'], 'docs/a.md')
        self.assertEqual(findings[0]['severity'], 'HIGH')

    def test_11_cli_version_and_json(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            main(['--version'])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), '0.1.0')
        code, out, _ = self.cli('--json')
        self.assertEqual(code, 0)
        self.assertEqual(set(json.loads(out)), {'status', 'claims', 'evidence', 'findings'})

    def test_11_errors(self):
        for args in [['missing'], ['--bogus'], ['--fail-on', 'LOW']]:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
        self.write('bad.py', 'def !!!')
        self.assertEqual(self.cli()[0], 1)
        (self.root / 'bad.py').unlink()
        original = Path.read_text
        def denied(path, *a, **kw):
            if path.name == 'README.md':
                raise PermissionError('denied')
            return original(path, *a, **kw)
        self.write('README.md', '')
        with patch.object(Path, 'read_text', denied):
            self.assertEqual(self.cli()[0], 1)

    def test_11_ignore_docs_and_evidence(self):
        self.write('README.md', 'plugin support')
        self.write('loader.py', GOOD[0])
        self.assertEqual(self.cli('--ignore', '*.py')[0], 2)
        self.assertEqual(self.cli('--ignore', 'README.md')[0], 0)
        self.assertEqual(audit(self.root, ['README.md'])['claims'], [])

    def test_11_text_verbose(self):
        self.write('README.md', 'plugin support')
        self.assertEqual(self.cli()[1], 'FAIL\ndocumented-plugin-claim-false HIGH\n')
        self.assertIn('HIGH README.md', self.cli('--verbose')[1])

    def test_11_module_entrypoint(self):
        result = subprocess.run([sys.executable, '-m', 'plugin_claim_audit', str(self.root)], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'PASS\n')

    def test_11_console_declaration(self):
        text = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('plugin-claim-audit = "plugin_claim_audit.cli:main"', text)

    def test_12_self_audit(self):
        result = audit(ROOT)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['claims'], [])

    def test_13_env_never_opened(self):
        marker = 'ENV_GUARD_MARKER plugin support'
        self.write('.env', marker)
        self.write('docs/.env', marker)
        original = Path.open
        def guarded(path, *args, **kwargs):
            if path.name == '.env':
                raise AssertionError('.env opened')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            code, out, err = self.cli('--json')
        self.assertEqual(code, 0)
        self.assertNotIn(marker, out + err)

    def test_aliases_and_additional_evidence_forms(self):
        sources = [
            'from importlib.metadata import entry_points as eps\neps()\ne.load()',
            'from stevedore.driver import DriverManager as DM\nDM("x")',
            'import pathlib as p, importlib as i\np.Path("plugins").iterdir()\ni.import_module(name)',
            'from pathlib import Path as P\nfrom importlib import import_module\nP(".").glob("plugins/*.py")\nimport_module(name)',
            'import glob, importlib\nglob.iglob("plugins/*")\nimportlib.import_module(name)',
            'import importlib\nself.plugins.append(importlib.import_module("x"))',
            'import importlib\nself.registry.register(importlib.import_module("x"))',
        ]
        self.write('README.md', 'plugin support')
        for source in sources:
            with self.subTest(source=source):
                self.write('app.py', source)
                self.assertEqual(self.cli()[0], 0)

    def test_test_sources_and_symlinks_excluded(self):
        self.write('README.md', 'plugin support')
        self.write('tests/loader.py', GOOD[0])
        self.write('test_loader.py', GOOD[0])
        self.write('ignored/loader.py', GOOD[0])
        (self.root / 'linked.py').symlink_to(self.root / 'ignored/loader.py')
        (self.root / 'linked_dir').symlink_to(self.root / 'ignored', target_is_directory=True)
        self.assertEqual(audit(self.root, ['ignored'])['evidence'], [])

    def test_all_phrases(self):
        for phrase in PLUGIN:
            self.assertEqual(doc_claims(phrase), {'PLUGIN'}, phrase)
        for phrase in NOPLUGIN:
            self.assertEqual(doc_claims(phrase), {'NOPLUGIN'}, phrase)
        self.assertEqual(doc_claims('no plugins, but plugin api'), {'NOPLUGIN', 'PLUGIN'})


if __name__ == '__main__':
    unittest.main()
