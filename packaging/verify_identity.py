#!/usr/bin/env python3
"""Verify final release bytes against the exact source revision and skill tree."""
import hashlib
import json
from pathlib import Path
import re
import sys


def skill_digest(root):
    digest = hashlib.sha256(b'omgs-skill/1\0')
    files = []
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('skill must contain only unlinked regular files')
        if path.is_file():
            files.append((path.relative_to(root).as_posix().encode('utf-8'), path))
    for name, path in sorted(files):
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, 'big'))
        digest.update(name)
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)
    return digest.hexdigest()


def verify(binary, skill, revision):
    expected = dict(version=(skill / 'VERSION').read_text().strip(),
                    build_revision=revision, skill_digest_format='omgs-skill/1',
                    bundled_skill_sha256=skill_digest(skill))
    records = re.findall(rb'OMGS_IDENTITY_V1:(\{[^\x00\r\n]*?\}):OMGS_IDENTITY_END',
                         binary.read_bytes())
    if not records or any(json.loads(record) != expected for record in records):
        raise ValueError(f'artifact identity mismatch: {binary}; expected {expected}')
    print(f'identity verified: {binary.name} revision={revision} skill={expected["bundled_skill_sha256"]}')


if __name__ == '__main__':
    revision, skill, *binaries = sys.argv[1:]
    if not binaries:
        raise SystemExit('at least one binary is required')
    for binary in binaries:
        verify(Path(binary), Path(skill), revision)
