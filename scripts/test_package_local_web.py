"""Cross-platform regression for the native embedded-asset checksum contract."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('packer', Path(__file__).with_name('package-local-web.py'))
packer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packer)


class EmbeddedUiDigest(unittest.TestCase):
    def test_mixed_case_asset_names_use_native_byte_order(self):
        items = [('assets/index-DYK.js', b'script'), ('assets/index-Do4.css', b'styles'), ('index.html', b'page')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in reversed(items):
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(data)
            expected = hashlib.sha256()
            for name, data in items:
                expected.update(name.encode() + b'\0')
                expected.update(len(data).to_bytes(8, 'little'))
                expected.update(data)
            self.assertEqual(packer.ui_digest(root), expected.hexdigest())
            (root / items[0][0]).write_bytes(b'changed')
            self.assertNotEqual(packer.ui_digest(root), expected.hexdigest())


class ChecksumFile(unittest.TestCase):
    def test_sha256_file_ends_in_lf_on_every_build_host(self):
        # A CRLF from a Windows build makes `sha256sum -c` look for "name\r".
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'najwa-windows-x64-release.zip'
            archive.write_bytes(b'archive')
            digest = packer.write_checksum(archive)
            self.assertEqual(archive.with_name(archive.name + '.sha256').read_bytes(),
                             f'{digest}  {archive.name}\n'.encode('ascii'))


def workspace(root, files):
    for name in files:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text('')
        os.utime(root / name, (1_000, 1_000))


def stale(root, executable):
    return executable.stat().st_mtime < packer.mtime(packer.newest_source(root, executable))


class StaleBuild(unittest.TestCase):
    def test_without_dep_info_any_workspace_source_manifest_or_lockfile_counts(self):
        files = ['Cargo.toml', 'Cargo.lock', 'apps/local-web/Cargo.toml', 'apps/local-web/build.rs',
                 'apps/local-web/src/main.rs', 'crates/najwa-core/Cargo.toml',
                 'crates/najwa-core/src/send/mod.rs', 'crates/najwa-mailbox/src/main.rs']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace(root, files)
            for stamp, name in enumerate(files, start=2_000):
                os.utime(root / name, (stamp, stamp))
                self.assertEqual(packer.newest_source(root, root / 'target/release/najwa-web'), root / name)

    def test_dep_info_listed_inputs_refuse_and_unlinked_crates_do_not(self):
        listed = ['apps/local-web/src/main.rs', 'crates/najwa-core/src/send dir/mod.rs']
        unlinked = ['crates/najwa-mailbox/Cargo.toml', 'crates/najwa-mailbox/src/main.rs']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'target/release/najwa-web'
            workspace(root, ['Cargo.toml', 'Cargo.lock', 'apps/local-web/Cargo.toml',
                             'crates/najwa-core/Cargo.toml', 'target/release/najwa-web', *listed, *unlinked])
            deps = ' '.join(str(root / name).replace(' ', '\\ ') for name in listed)
            executable.with_suffix('.d').write_text(f'{executable}: {deps}\n\n')
            os.utime(executable, (2_000, 2_000))
            self.assertFalse(stale(root, executable))
            for name in unlinked:
                os.utime(root / name, (3_000, 3_000))
            self.assertFalse(stale(root, executable))
            for name in [*listed, 'crates/najwa-core/Cargo.toml', 'Cargo.lock']:
                os.utime(root / name, (3_000, 3_000))
                self.assertTrue(stale(root, executable), name)
                os.utime(root / name, (1_000, 1_000))
            (root / listed[1]).unlink()
            self.assertTrue(stale(root, executable))


class HardwarePolicy(unittest.TestCase):
    def test_legacy_or_software_packages_are_refused(self):
        for os_name in ['windows', 'linux', 'macos']:
            for info in [{}, {'keyProtection': 'os-keystore', 'softwareFallback': False},
                         {'keyProtection': 'hardware-preferred', 'hardwareBackend': 'tpm2', 'softwareFallback': True},
                         {'keyProtection': 'hardware-preferred', 'hardwareBackend': 'tpm2'}]:
                with self.assertRaises(SystemExit):
                    packer.require_hardware_policy(info, os_name)

    def test_hardware_policy_must_match_platform(self):
        tpm = {'keyProtection': 'hardware-preferred', 'hardwareBackend': 'tpm2', 'softwareFallback': 'explicit-approval'}
        enclave = {'keyProtection': 'hardware-preferred', 'hardwareBackend': 'secure-enclave', 'softwareFallback': 'explicit-approval'}
        for os_name in ['windows', 'linux']:
            packer.require_hardware_policy(tpm, os_name)
            with self.assertRaises(SystemExit):
                packer.require_hardware_policy(enclave, os_name)
        packer.require_hardware_policy(enclave, 'macos')
        with self.assertRaises(SystemExit):
            packer.require_hardware_policy(tpm, 'macos')


if __name__ == '__main__':
    unittest.main()
