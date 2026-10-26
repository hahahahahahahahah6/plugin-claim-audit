"""Offline AST and Markdown auditing; source is never executed."""
import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import sys

from . import __version__

PLUGIN = (
    'plugin support', 'supports plugins', 'supports plugin', 'plugin system',
    'plugins supported', 'plugin supported', 'third party plugins',
    'third party plugin', 'custom plugins', 'custom plugin', 'plugin api',
    'plugin architecture', 'plugin framework', 'plugin based', 'plugin model',
    'extensible through plugins', 'extensible via plugins',
    'extensible with plugins', 'extendable with plugins',
    'extendable through plugins', 'extend with plugins', 'write plugins',
    'write your own plugin', 'write your own plugins', 'install plugins',
    'install third party plugins', 'load plugins', 'loads plugins',
    'loading plugins', 'plugin discovery', 'discovers plugins',
    'pluggable architecture', 'pluggable system', 'supports third party extensions',
)
NOPLUGIN = (
    'no plugin support', 'does not support plugins', 'does not support plugin',
    'no plugins', 'no plugin system', 'plugins are not supported',
    'plugin support is not available', 'not extensible', 'not extendable',
    'cannot be extended', 'no third party plugins', 'no custom plugins',
    'does not load plugins', 'no plugin api',
)


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)) + r')\b')


def doc_claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fence:
            if re.match(r'^\s{0,3}' + re.escape(fence[0]) + '{' + str(len(fence)) + r',}\s*$', line):
                fence = None
            continue
        if match:
            fence = match.group(1)
            lines.append('')
        else:
            lines.append(line)
    result = set()
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        normal = re.sub(r'\s+', ' ', paragraph.lower().replace('-', ' '))
        if pattern(NOPLUGIN).search(normal):
            result.add('NOPLUGIN')
        normal = pattern(NOPLUGIN).sub(' ', normal)
        if pattern(PLUGIN).search(normal):
            result.add('PLUGIN')
    return result


def evidence_kinds(source, filename):
    tree = ast.parse(source, filename=filename)
    aliases = {}
    pluggy = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
                pluggy |= alias.name == 'pluggy'
        elif isinstance(node, ast.ImportFrom):
            pluggy |= node.module == 'pluggy'
            for alias in node.names:
                aliases[alias.asname or alias.name] = (node.module or '') + '.' + alias.name

    def dotted(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return dotted(node.value) + '.' + node.attr
        if isinstance(node, ast.Call):
            return dotted(node.func)
        return ''

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    names = [dotted(n.func) for n in calls]
    attr = lambda name: any(isinstance(n.func, ast.Attribute) and n.func.attr == name for n in calls)
    dynamic = any(dotted(n.func) == 'importlib.import_module' and n.args and not (isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)) for n in calls)
    imported = 'importlib.import_module' in names
    scans = {'os.listdir', 'os.scandir', 'glob.glob', 'glob.iglob', 'pathlib.Path.glob', 'pathlib.Path.iterdir'}
    scan = False
    registry = False
    for n in calls:
        if dotted(n.func) in scans:
            # Include the Path constructor receiver as well as explicit arguments.
            scan |= any(isinstance(c, ast.Constant) and isinstance(c.value, str) and 'plugin' in c.value.lower() for c in ast.walk(n))
        if isinstance(n.func, ast.Attribute) and n.func.attr in {'append', 'register', 'add'}:
            registry |= isinstance(n.func.value, ast.Attribute) and n.func.value.attr in {'plugins', 'registry'}
    for n in ast.walk(tree):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, (ast.AnnAssign, ast.AugAssign)) else []
        for target in targets:
            for t in ast.walk(target):
                if isinstance(t, ast.Subscript) and 'plugin' in dotted(t.value).lower():
                    registry = True
    result = []
    if 'importlib.metadata.entry_points' in names and attr('load'):
        result.append('entry-points')
    if pluggy and any(n.endswith('PluginManager') for n in names) and attr('register'):
        result.append('pluggy')
    if any(n in {'stevedore.extension.ExtensionManager', 'stevedore.driver.DriverManager', 'stevedore.ExtensionManager', 'stevedore.DriverManager'} for n in names):
        result.append('stevedore')
    if scan and dynamic:
        result.append('directory')
    if registry and imported:
        result.append('registry')
    return result


def audit(root, ignores=()):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('ROOT must be a directory')
    claims, evidence = [], []
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not Path(directory, d).is_symlink() and not any(fnmatch.fnmatchcase(Path(directory, d).relative_to(root).as_posix(), g) for g in ignores))
        for name in sorted(files):
            path = Path(directory, name)
            rel = path.relative_to(root)
            posix = rel.as_posix()
            if path.is_symlink() or name == '.env' or any(fnmatch.fnmatchcase(posix, g) for g in ignores):
                continue
            if (posix == 'README.md' or ('docs' in rel.parts[:-1] and path.suffix.lower() == '.md')):
                for family in sorted(doc_claims(path.read_text(encoding='utf-8'))):
                    claims.append({'family': family, 'path': posix})
            if path.suffix == '.py' and 'tests' not in rel.parts and not name.startswith('test_'):
                for kind in evidence_kinds(path.read_text(encoding='utf-8'), posix):
                    evidence.append({'kind': kind, 'path': posix})
    findings = []
    for family, false in [('PLUGIN', not evidence), ('NOPLUGIN', bool(evidence))]:
        candidates = [c for c in claims if c['family'] == family]
        if false and candidates:
            chosen = min(candidates, key=lambda c: ('tests' in Path(c['path']).parts, c['path']))
            findings.append({'rule': 'documented-' + ('plugin' if family == 'PLUGIN' else 'no-plugin') + '-claim-false', 'severity': 'MEDIUM' if 'tests' in Path(chosen['path']).parts else 'HIGH', 'path': chosen['path']})
    return {'status': 'FAIL' if findings else 'PASS', 'evidence': evidence, 'claims': claims, 'findings': findings}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv=None):
    parser = Parser(prog='plugin-claim-audit')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', nargs='+', action='extend', default=[])
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='MEDIUM')
    parser.add_argument('--version', action='version', version=__version__)
    try:
        args = parser.parse_args(argv)
        result = audit(args.root, args.ignore)
        if args.json:
            print(json.dumps(result))
        else:
            print(result['status'])
            for f in result['findings']:
                print(f['rule'], f['severity'], *([f['path']] if args.verbose else []))
        return 2 if any(f['severity'] == 'HIGH' or args.fail_on == 'MEDIUM' for f in result['findings']) else 0
    except (ValueError, OSError, SyntaxError, UnicodeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 1
