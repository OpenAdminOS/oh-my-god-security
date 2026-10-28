#!/usr/bin/env python3
"""Local-bundle installer regressions. Test verifiers exist only in disposable copies."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import sys
import subprocess
import tempfile
import unittest

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
ALLOW_TEST_VERIFIERS = False


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Installers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='omgs-installer-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.skill = self.root / 'skill'
        shutil.copytree(ROOT / 'skill', self.skill)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.windows = os.name == 'nt'
        self.asset = 'omgs-x86_64-pc-windows-msvc.exe' if self.windows else 'omgs-aarch64-apple-darwin'
        self.executor = 'mxc-1.0.1-windows-x64.exe' if self.windows else 'mxc-1.0.1-macos-arm64'
        self.binary = self.bundle / self.asset
        built = ROOT / 'target/debug' / ('omgs.exe' if self.windows else 'omgs')
        shutil.copyfile(built, self.binary)
        self.binary.chmod(0o755)
        (self.bundle / self.executor).write_bytes(b'executor fixture\n')
        shutil.copyfile(ROOT / 'skill/MXC-LICENSE.txt', self.bundle / 'MXC-LICENSE.txt')
        self.original = sha(self.binary)
        self.executor_hash = sha(self.bundle / self.executor)
        self.checksums()
        self.env = dict(os.environ, OMGS_HOME=str(self.root / 'home'), OMGS_RELEASE_BASE=str(self.bundle),
                        RUSTUP_AUTO_INSTALL='0', GH_TOKEN='', GITHUB_TOKEN='',
                        GH_CONFIG_DIR=str(self.root / 'gh-config'))
        self.script = self.skill / 'scripts' / ('install.ps1' if self.windows else 'install.sh')

    def checksums(self):
        (self.bundle / 'SHA256SUMS').write_text(''.join(
            f'{sha(p)}  {p.name}\n' for p in sorted(self.bundle.iterdir()) if p.name != 'SHA256SUMS'))

    def fake_verifiers(self):
        if not ALLOW_TEST_VERIFIERS:
            raise RuntimeError('Test copies require explicit --allow-test-verifiers')
        text = self.script.read_text()
        pins = self.skill / 'mxc-pins.txt'
        rows = pins.read_text().splitlines()
        pins.write_text('\n'.join(' '.join(row.split()[:-1] + [self.executor_hash])
                                 if self.executor in row else row for row in rows) + '\n')
        if self.windows:
            # This function is injected only into this disposable script copy.
            shim = f'''
function Test-AuthenticodeSignature([string]$LiteralPath) {{
    $hash = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $subject = if ($hash -ceq '{self.original}') {{ $OmgsSubject }} else {{ $MicrosoftSubject }}
    $status = if ($hash -ceq '{self.original}' -or $hash -ceq '{self.executor_hash}') {{ 'Valid' }} else {{ 'HashMismatch' }}
    return [pscustomobject]@{{ Status=$status; SignerCertificate=[pscustomobject]@{{ Subject=$subject }} }}
}}
'''
            text = shim + text.replace('Microsoft.PowerShell.Security\\Get-AuthenticodeSignature', 'Test-AuthenticodeSignature')
        else:
            # Exercise macOS publisher verification on Linux too, without a production override.
            text = text.replace('os=$(uname -s)', 'os=Darwin').replace('arch=$(uname -m)', 'arch=arm64')
            shim = self.root / 'codesign-test'
            shim.write_text(f'''#!/bin/sh
case "$*" in *--verify*--strict*subject.OU*) ;; *) exit 1 ;; esac
for last do :; done
if command -v sha256sum >/dev/null; then hash=$(sha256sum "$last"); else hash=$(shasum -a 256 "$last"); fi
case "${{hash%% *}}" in {self.original}|{self.executor_hash}) exit 0 ;; *) exit 1 ;; esac
''')
            shim.chmod(0o755)
            text = text.replace('/usr/bin/codesign', '"' + str(shim) + '"')
        self.script.write_text(text)

    def run_install(self, answer='yes\n', real=False, extra=()):
        script = ROOT / 'skill/scripts' / self.script.name if real else self.script
        command = ['powershell', '-NoProfile', '-File', str(script)] if self.windows else ['sh', str(script)]
        return subprocess.run(command + list(extra), input=answer, text=True, capture_output=True,
                              env=self.env, timeout=60)

    def assert_failed(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)
        self.assertFalse((self.root / 'home/bin/omgs').exists())
        self.assertFalse((self.root / 'home/bin/omgs.exe').exists())

    def test_declined_consent_makes_no_download(self):
        self.env['OMGS_RELEASE_BASE'] = str(self.root / 'does-not-exist')
        self.assert_failed(self.run_install('no\n', real=True), 'cancelled before downloads')

    def test_valid_bundle_installs_and_reports(self):
        self.fake_verifiers()
        out = self.run_install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for text in ['Installed omgs 0.1.0:', 'Installed MXC 1.0.1:', 'SHA256SUMS verified:', 'Publisher signature verified:', 'provenance: unverified']:
            self.assertIn(text, out.stdout + out.stderr)

    def assert_existing_install_survives(self, failure):
        self.fake_verifiers()
        # Use a custom root with spaces and seed all three previous files.
        home = self.root / 'custom install'
        self.env['OMGS_HOME'] = str(home)
        previous = {
            Path('bin') / ('omgs.exe' if self.windows else 'omgs'): b'previous binary',
            Path('mxc/1.0.1') / ('wxc-exec.exe' if self.windows else 'mxc-exec-mac'): b'previous executor',
            Path('mxc/1.0.1/MXC-LICENSE.txt'): b'previous notice',
        }
        for relative, data in previous.items():
            path = home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        text = self.script.read_text()
        if self.windows:
            marker = '    Checksum $asset $stagedOmgs'
            injection = {
                'abort': "    throw 'simulated staging failure'",
                'checksum': "    [IO.File]::WriteAllText($stagedLicense, 'corrupt staged bytes')",
                'signature': "    function Test-AuthenticodeSignature { return [pscustomobject]@{ Status='HashMismatch'; SignerCertificate=$null } }",
            }[failure]
        else:
            marker = 'checksum "$asset" "$staged_omgs"'
            injection = {
                'abort': "echo 'simulated staging failure' >&2; exit 1",
                'checksum': "printf 'corrupt staged bytes' > \"$staged_license\"",
                'signature': "MICROSOFT_TEAM_ID=wrong-staged-signer\nverify_signature() { echo 'publisher signature rejected: staged file' >&2; exit 1; }",
            }[failure]
        self.assertEqual(text.count(marker), 1)
        self.script.write_text(text.replace(marker, injection + '\n' + marker))
        out = self.run_install()
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        expected = {'abort': 'simulated staging failure', 'checksum': 'checksum mismatch',
                    'signature': 'publisher signature rejected'}[failure]
        self.assertIn(expected, out.stdout + out.stderr)
        for relative, data in previous.items():
            self.assertEqual((home / relative).read_bytes(), data)
        self.assertEqual({p.relative_to(home) for p in home.rglob('*') if p.is_file()}, set(previous))

    def test_failure_after_staging_preserves_previous_install(self):
        self.assert_existing_install_survives('abort')

    def test_staged_checksum_failure_preserves_previous_install(self):
        self.assert_existing_install_survives('checksum')

    def test_staged_signature_failure_preserves_previous_install(self):
        self.assert_existing_install_survives('signature')

    def test_successful_replacement_preserves_complete_bytes(self):
        self.fake_verifiers()
        for _ in range(2):
            out = self.run_install()
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            home = Path(self.env['OMGS_HOME'])
            files = [p for p in home.rglob('*') if p.is_file()]
            self.assertEqual(len(files), 3)
            binary = home / 'bin' / ('omgs.exe' if self.windows else 'omgs')
            self.assertEqual(sha(binary), self.original)
            self.assertIn(str(binary), out.stdout)
            executor = next(p for p in files if p.name not in ('omgs', 'omgs.exe', 'MXC-LICENSE.txt'))
            self.assertEqual(sha(executor), self.executor_hash)
            self.assertEqual(sha(home / 'mxc/1.0.1/MXC-LICENSE.txt'), sha(self.bundle / 'MXC-LICENSE.txt'))

    def test_authenticated_attestation_failure_is_unverified(self):
        self.fake_verifiers()
        if self.windows:
            text = self.script.read_text()
            text = "function gh { if ($args[0] -eq 'auth') { $global:LASTEXITCODE=0 } else { $global:LASTEXITCODE=1 } }\n" + text
            self.script.write_text(text)
        else:
            tools = self.root / 'tools'
            tools.mkdir()
            gh = tools / 'gh'
            gh.write_text('#!/bin/sh\n[ "$1" = auth ]\n')
            gh.chmod(0o755)
            self.env['PATH'] = str(tools) + os.pathsep + self.env['PATH']
        out = self.run_install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('provenance: unverified', out.stdout + out.stderr)
        self.assertIn('Installed omgs 0.1.0:', out.stdout)

    def test_unavailable_authentication_is_unverified(self):
        self.fake_verifiers()
        if self.windows:
            self.script.write_text("function gh { Write-Error 'Authentication unavailable'; $global:LASTEXITCODE=1 }\n" + self.script.read_text())
        else:
            tools = self.root / 'tools'
            tools.mkdir()
            gh = tools / 'gh'
            gh.write_text('#!/bin/sh\necho "Authentication unavailable" >&2\nexit 1\n')
            gh.chmod(0o755)
            self.env['PATH'] = str(tools) + os.pathsep + self.env['PATH']
        out = self.run_install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('provenance: unverified', out.stdout + out.stderr)
        self.assertIn('Installed omgs 0.1.0:', out.stdout)

    def test_tampered_binary_with_forged_checksums_fails_signature(self):
        self.fake_verifiers()
        with self.binary.open('ab') as stream:
            stream.write(b'tampered')
        self.checksums()
        self.assert_failed(self.run_install(), 'publisher signature rejected')

    def test_version_mismatch_reported(self):
        self.fake_verifiers()
        (self.skill / 'VERSION').write_text('99.0.0\n')
        self.assert_failed(self.run_install(), 'version mismatch: skill expects omgs 99.0.0; binary reports omgs 0.1.0')

    def test_executor_pin_rejects_forged_checksums(self):
        self.fake_verifiers()
        (self.bundle / self.executor).write_bytes(b'wrong executor')
        self.checksums()
        self.assert_failed(self.run_install(), 'MXC pin mismatch')

    def test_real_installer_does_not_honor_test_override(self):
        # Plant the same proposed bypasses in the real process. None may authorize a fixture.
        self.env.update(OMGS_TEST_ALLOW_UNSIGNED='1', OMGS_TEST_CODESIGN='true',
                        OMGS_TEST_AUTHENTICODE='Valid', OMGS_TEST_MXC_SHA256=self.executor_hash)
        if not self.windows and platform.system() == 'Linux':
            arch = 'aarch64' if platform.machine() in ('aarch64', 'arm64') else 'x86_64'
            linux_asset = f'omgs-{arch}-unknown-linux-gnu'
            shutil.copyfile(self.binary, self.bundle / linux_asset)
            (self.bundle / f'mxc-1.0.1-linux-{"arm64" if arch == "aarch64" else "x64"}').write_bytes(b'executor fixture\n')
            self.checksums()
        self.assert_failed(self.run_install(real=True), 'publisher signature rejected' if self.windows or platform.system() == 'Darwin' else 'MXC pin mismatch')
        out = self.run_install(real=True, extra=['--allow-test-verifiers'])
        self.assert_failed(out, 'No installer arguments are accepted')

    def test_checksum_mismatch_rejected_before_signature(self):
        self.fake_verifiers()
        with self.binary.open('ab') as stream:
            stream.write(b'tampered')
        self.assert_failed(self.run_install(), 'checksum mismatch')

    def test_consent_text_is_identical(self):
        shell = (ROOT / 'skill/scripts/install.sh').read_text()
        block = shell.split("cat <<'CONSENT'\n")[1].split('\nCONSENT')[0]
        self.assertIn(block, (ROOT / 'skill/scripts/install.ps1').read_text())
        self.assertIn(block, (ROOT / 'skill/SKILL.md').read_text())
        for script in ['install.sh', 'install.ps1']:
            source = (ROOT / 'skill/scripts' / script).read_text()
            self.assertNotIn('OMGS_TEST_', source)
            self.assertNotIn('Test-AuthenticodeSignature', source)
        self.assertIn('/usr/bin/codesign --verify --strict', shell)
        self.assertIn('Microsoft.PowerShell.Security\\Get-AuthenticodeSignature', (ROOT / 'skill/scripts/install.ps1').read_text())

    def test_package_templates_render_final_hashes(self):
        spec = importlib.util.spec_from_file_location('release', ROOT / 'packaging/release.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Model final signed asset hashes without claiming these fixture bytes are distributable.
        names = ['omgs-aarch64-apple-darwin', 'omgs-x86_64-apple-darwin',
                 'omgs-aarch64-unknown-linux-gnu', 'omgs-x86_64-unknown-linux-gnu',
                 'omgs-x86_64-pc-windows-msvc.exe']
        for name in names:
            (self.bundle / name).write_bytes(b'final signed asset fixture')
        # Substitute only fixture hashes in this in-memory test module.
        rows = module.pins()
        for row in rows:
            (self.bundle / row[2]).write_bytes(b'executor fixture')
            row[3] = sha(self.bundle / row[2])
        module.pins = lambda: rows
        output = self.root / 'rendered'
        module.packages('v0.1.0', self.bundle, output)
        self.assertEqual(len(list(output.iterdir())), 4)
        formula = (output / 'omgs.rb').read_text()
        self.assertNotIn('@SHA_', formula)
        self.assertIn(sha(self.bundle / names[0]), formula)
        self.assertIn('mxc-1.0.1-macos-arm64', formula)
        with self.assertRaises(ValueError):
            module.packages('v99.0.0', self.bundle, output)

    def test_release_pins_match_rust(self):
        spec = importlib.util.spec_from_file_location('release', ROOT / 'packaging/release.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(len(module.pins()), 5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-test-verifiers', action='store_true', required=True,
                        help='Allow fake verifiers only in disposable installer copies')
    options, rest = parser.parse_known_args()
    ALLOW_TEST_VERIFIERS = options.allow_test_verifiers
    unittest.main(argv=[__file__] + rest)
