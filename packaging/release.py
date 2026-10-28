#!/usr/bin/env python3
"""Verify immutable MXC mirrors and render package metadata from final signed bytes."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ZIP_SHA = '0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pins():
    source = (ROOT / 'src/sandbox.rs').read_text()
    rows = [line.split() for line in (ROOT / 'skill/mxc-pins.txt').read_text().splitlines()
            if line and not line.startswith('#')]
    if len(rows) != 5 or any(len(row) != 4 for row in rows) or len({row[2] for row in rows}) != 5:
        raise ValueError('Expected five distinct MXC platform assets')
    if ZIP_SHA not in source or 'pub const MXC_VERSION: &str = "1.0.1"' not in source:
        raise ValueError('MXC version or archive pin diverged')
    for _, _, _, sha in rows:
        if not re.fullmatch('[0-9a-f]{64}', sha) or sha not in source:
            raise ValueError('MXC pins diverged')
    return rows


def mirror(archive, out):
    if digest(archive) != ZIP_SHA:
        raise ValueError('MXC archive SHA-256 mismatch')
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for _, member, asset, sha in pins():
            data = bundle.read(member)
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError(f'MXC executor SHA-256 mismatch: {member}')
            (out / asset).write_bytes(data)
    shutil.copyfile(ROOT / 'skill/MXC-LICENSE.txt', out / 'MXC-LICENSE.txt')


def packages(version, assets, out):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?', version):
        raise ValueError('Package-manager assets require a semantic version')
    if version != 'v' + (ROOT / 'skill/VERSION').read_text().strip():
        raise ValueError('Release tag and skill/VERSION differ')
    values = {'VERSION': version[1:], 'BASE': f'https://github.com/OpenAdminOS/oh-my-god-security/releases/download/{version}'}
    for path in sorted(assets.iterdir()):
        if path.name.startswith(('omgs-', 'mxc-')):
            values['SHA_' + path.name] = digest(path)
    for _, _, asset, sha in pins():
        if values.get('SHA_' + asset) != sha:
            raise ValueError(f'MXC pin mismatch: {asset}')
    out.mkdir(parents=True, exist_ok=True)
    for template in sorted((ROOT / 'packaging').glob('*.in')):
        content = template.read_text()
        content = re.sub(r'@([^@\n]+)@', lambda match: values[match[1]], content)
        (out / template.name.removesuffix('.in')).write_text(content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    m = sub.add_parser('mirror')
    m.add_argument('archive', type=Path)
    m.add_argument('out', type=Path)
    p = sub.add_parser('packages')
    p.add_argument('version')
    p.add_argument('assets', type=Path)
    p.add_argument('out', type=Path)
    args = parser.parse_args()
    if args.command == 'mirror':
        mirror(args.archive, args.out)
    else:
        packages(args.version, args.assets, args.out)
