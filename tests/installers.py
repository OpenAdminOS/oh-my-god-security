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
        self.tmp = tempfile.TemporaryDirectory(prefix='omgs-installer-',
                                               dir=os.environ['USERPROFILE'] if os.name == 'nt' else None)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        if os.name == 'nt':
            # Python may reserve temp directories with OWNER RIGHTS and an
            # elevated token's Administrators owner. Give only this newly
            # created disposable fixture the product's explicit user DACL.
            escaped = str(self.root).replace("'", "''")
            command = f"""
$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath '{escaped}' -AclObject $acl
"""
            subprocess.run(['powershell', '-NoProfile', '-Command', command],
                           text=True, capture_output=True, check=True)
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
        # Exercise profile staging only inside this disposable fixture.
        profile = self.root / 'profile'
        profile.mkdir(mode=0o700)
        self.env['LOCALAPPDATA' if self.windows else 'HOME'] = str(profile)
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

    def test_unsafe_staging_ancestor_is_refused_before_download(self):
        self.fake_verifiers()
        profile = Path(self.env['LOCALAPPDATA' if self.windows else 'HOME'])
        self.make_staging_unsafe(profile)
        self.env['OMGS_RELEASE_BASE'] = str(self.root / 'missing-bundle')
        self.assert_failed(self.run_install(), 'Unsafe staging')

    def make_staging_unsafe(self, path):
        if self.windows:
            escaped = str(path).replace("'", "''")
            command = f"""
$ErrorActionPreference = 'Stop'
$a = Get-Acl -LiteralPath '{escaped}'
$s = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s, 'DeleteSubdirectoriesAndFiles', 'Allow'))
Set-Acl -LiteralPath '{escaped}' -AclObject $a
"""
            subprocess.run(['powershell', '-NoProfile', '-Command', command], check=True, capture_output=True)
        else:
            path.chmod(0o777)

    @unittest.skipUnless(platform.system() == 'Darwin', 'macOS ACLs')
    def test_staging_ancestor_mutation_acl_is_refused(self):
        self.fake_verifiers()
        profile = Path(self.env['HOME'])
        subprocess.run(['/bin/chmod', '+a', 'everyone allow delete_child', str(profile)], check=True)
        try:
            self.assert_failed(self.run_install(), 'Unsafe staging')
        finally:
            subprocess.run(['/bin/chmod', '-N', str(profile)], check=True)

    def test_staging_ancestor_swap_after_verification_is_refused(self):
        self.fake_verifiers()
        text = self.script.read_text()
        if self.windows:
            marker = '    Admit-Staging $tmp'
            injection = """    $parent = Split-Path $tmp -Parent
    $moved = $parent + '-moved'
    Move-Item -LiteralPath $parent -Destination $moved
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $a = Get-Acl -LiteralPath $parent
    $s = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s, 'DeleteSubdirectoriesAndFiles', 'Allow'))
    Set-Acl -LiteralPath $parent -AclObject $a
    Move-Item -LiteralPath (Join-Path $moved (Split-Path $tmp -Leaf)) -Destination $tmp
"""
        else:
            marker = 'admit_staging "$tmp"\n[ "$(digest'
            injection = '''mv "$staging_parent" "$staging_parent-moved"
mkdir "$staging_parent"
chmod 0777 "$staging_parent"
mv "$staging_parent-moved/$(basename "$tmp")" "$tmp"
'''
        self.assertEqual(text.count(marker), 1)
        self.script.write_text(text.replace(marker, injection + marker))
        self.assert_failed(self.run_install(), 'Unsafe staging')

    def test_source_mutation_after_verification_is_refused_by_install_self(self):
        self.fake_verifiers()
        text = self.script.read_text()
        marker = ('    # The verified executable owns admission' if self.windows else
                  '# The verified executable owns admission')
        injection = ("    [IO.File]::WriteAllText((Join-Path $tmp 'MXC-LICENSE.txt'), 'changed after verification')\n"
                     if self.windows else
                     "printf 'changed after verification' > \"$tmp/MXC-LICENSE.txt\"\n")
        self.script.write_text(text.replace(marker, injection + marker))
        self.assert_failed(self.run_install(), 'verified source checksum mismatch')

    def assert_existing_install_survives(self, failure):
        self.fake_verifiers()
        # Use a custom root with spaces and seed all three previous files.
        home = self.root / 'custom install'
        self.env['OMGS_HOME'] = str(home)
        initial = self.run_install()
        self.assertEqual(initial.returncode, 0, initial.stdout + initial.stderr)
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
            marker = '    $actual = & (Join-Path $tmp $asset) --version'
            injection = {
                'abort': "    throw 'simulated staging failure'",
                'checksum': "    [IO.File]::WriteAllText((Join-Path $tmp 'MXC-LICENSE.txt'), 'corrupt staged bytes')\n    Checksum 'MXC-LICENSE.txt'",
                'signature': "    function Test-AuthenticodeSignature { return [pscustomobject]@{ Status='HashMismatch'; SignerCertificate=$null } }\n    Signature (Join-Path $tmp $asset) $OmgsSubject",
            }[failure]
        else:
            marker = 'chmod 0755 "$tmp/$asset"'
            injection = {
                'abort': "echo 'simulated staging failure' >&2; exit 1",
                'checksum': "printf 'corrupt staged bytes' > \"$tmp/MXC-LICENSE.txt\"\nchecksum MXC-LICENSE.txt",
                'signature': "verify_signature() { echo 'publisher signature rejected: staged file' >&2; exit 1; }\nverify_signature \"$tmp/$asset\" \"$OMGS_TEAM_ID\"",
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

    @unittest.skipIf(os.name == 'nt', 'Unix permissions')
    def test_new_directories_are_private_under_permissive_umasks(self):
        self.fake_verifiers()
        for mask in (0o022, 0o000):
            home = self.root / f'home-{mask:o}'
            self.env['OMGS_HOME'] = str(home)
            old = os.umask(mask)
            try:
                out = self.run_install()
            finally:
                os.umask(old)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            for directory in [home] + [p for p in home.rglob('*') if p.is_dir()]:
                self.assertEqual(directory.stat().st_mode & 0o7777, 0o700, str(directory))

    @unittest.skipIf(os.name == 'nt', 'Unix permissions')
    def test_insecure_custom_home_and_ancestors_are_rejected(self):
        self.fake_verifiers()
        for relative, mode in [('bin', 0o777), ('mxc', 0o775), ('', 0o777)]:
            with self.subTest(relative=relative):
                home = self.root / ('unsafe-' + (relative or 'root'))
                unsafe = home / relative
                unsafe.mkdir(parents=True)
                unsafe.chmod(mode)
                self.env['OMGS_HOME'] = str(home)
                out = self.run_install()
                self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertIn(str(unsafe), out.stderr)
                self.assertIn('not be group- or world-writable', out.stderr)
                self.assertEqual(unsafe.stat().st_mode & 0o7777, mode)
                self.assertFalse(any(p.is_file() for p in home.rglob('*')))

    @unittest.skipIf(os.name == 'nt', 'Unix publication paths')
    def test_sticky_bin_and_precreated_leaf_directory_or_symlink_are_refused(self):
        self.fake_verifiers()
        for kind in ('sticky', 'directory', 'symlink', 'ancestor-link'):
            home = self.root / kind
            bin_dir = home / 'bin'
            bin_dir.mkdir(parents=True)
            binary = bin_dir / 'omgs'
            if kind == 'sticky':
                bin_dir.chmod(0o1777)
            elif kind == 'directory':
                binary.mkdir()
            elif kind == 'symlink':
                binary.symlink_to(self.binary)
            else:
                alias = self.root / 'alias'
                alias.symlink_to(home, target_is_directory=True)
                home = alias
            self.env['OMGS_HOME'] = str(home)
            out = self.run_install()
            self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
            expected = (home if kind == 'ancestor-link' else
                        bin_dir if kind == 'sticky' else binary)
            self.assertIn(str(expected), out.stderr)
            self.assertFalse(list(bin_dir.glob('.omgs-*')))
            self.assertEqual(sha(self.binary), self.original)

    @unittest.skipUnless(os.name == 'nt', 'Windows ACLs')
    def test_windows_created_directories_have_owner_only_protected_dacl(self):
        self.fake_verifiers()
        out = self.run_install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        home = self.env['OMGS_HOME'].replace("'", "''")
        # A safe existing SYSTEM grant is admitted, but must not survive the
        # replacement. File.Replace would retain it from the old executable.
        seed = f"""
$ErrorActionPreference = 'Stop'
$p = Join-Path '{home}' 'bin/omgs.exe'
$a = Get-Acl -LiteralPath $p
$s = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s, 'FullControl', 'Allow'))
Set-Acl -LiteralPath $p -AclObject $a
"""
        subprocess.run(['powershell', '-NoProfile', '-Command', seed],
                       text=True, capture_output=True, check=True)
        replacement = self.run_install()
        self.assertEqual(replacement.returncode, 0, replacement.stdout + replacement.stderr)
        command = f"""
$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root = Get-Item -LiteralPath '{home}'
foreach ($d in @($root) + @(Get-ChildItem -LiteralPath $root.FullName -Recurse)) {{
    $a = Get-Acl -LiteralPath $d.FullName
    if (-not $a.AreAccessRulesProtected -or $a.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user) {{ throw 'Directory owner or protection mismatch' }}
    $rules = @($a.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $user -or $rules[0].FileSystemRights -ne 'FullControl') {{ throw 'Directory is not owner-only' }}
}}
"""
        subprocess.run(['powershell', '-NoProfile', '-Command', command],
                       text=True, capture_output=True, check=True)

    @unittest.skipUnless(os.name == 'nt', 'Windows ACLs')
    def test_windows_users_write_acl_is_rejected(self):
        self.fake_verifiers()
        home = Path(self.env['OMGS_HOME'])
        # First create the installation with the production private DACL.
        out = self.run_install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        destination = home / 'bin' / 'omgs.exe'
        command = f"""
$p = '{str(destination).replace("'", "''")}'
$a = Get-Acl -LiteralPath $p
$s = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$r = [Security.AccessControl.FileSystemAccessRule]::new($s, 'Write', 'Allow')
$a.AddAccessRule($r)
Set-Acl -LiteralPath $p -AclObject $a
"""
        subprocess.run(['powershell', '-NoProfile', '-Command', command],
                                text=True, capture_output=True, check=True)
        out = self.run_install()
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('storage is writable by another principal', out.stderr)
        self.assertIn(str(destination), out.stderr)

    @unittest.skipUnless(os.name == 'nt', 'Windows sharing violations')
    def test_locked_destinations_preserve_existing_files_and_clean_staging(self):
        self.fake_verifiers()
        original_script = self.script.read_text()
        home = Path(self.env['OMGS_HOME'])
        for relative in ('bin/omgs.exe', 'mxc/1.0.1/wxc-exec.exe'):
            self.script.write_text(original_script)
            out = self.run_install()
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            destination = home / relative
            destination.write_bytes(b'previous locked file')
            escaped = str(destination).replace("'", "''")
            injection = f"    $held = [IO.File]::Open('{escaped}', 'Open', 'Read', 'Read')\n"
            marker = '    # The verified executable owns admission and exact-path publication.'
            text = original_script.replace(marker, injection + marker)
            text = text.replace('} finally {\n    Remove-Item -LiteralPath $tmp', '} finally {\n    if ($held) { $held.Dispose() }\n    Remove-Item -LiteralPath $tmp')
            self.script.write_text(text)
            out = self.run_install()
            message = ' '.join((out.stdout + out.stderr).split())
            self.assertNotEqual(out.returncode, 0, message)
            for expected in ('Publication failed', str(destination), 'running omgs.exe or MXC',
                             'Stop it and retry', 'mix of old and new files'):
                self.assertIn(expected, message)
            self.assertEqual(destination.read_bytes(), b'previous locked file')
            files = [p for p in home.rglob('*') if p.is_file()]
            self.assertEqual(len(files), 3, files)
            for file in files:
                if file != destination:
                    expected = (self.original if file.name == 'omgs.exe' else
                                self.executor_hash if file.name == 'wxc-exec.exe' else
                                sha(self.bundle / 'MXC-LICENSE.txt'))
                    self.assertEqual(sha(file), expected)

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
