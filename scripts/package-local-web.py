"""Package native host builds. Distributed apps contain no launcher scripts."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import shutil
import subprocess
import tarfile
import zipfile
import importlib.util


def ui_digest(root):
    digest = hashlib.sha256()
    # WindowsPath ordering folds case. Rust's embedded asset names use an
    # explicit UTF-8 byte order, identical on every supported build host.
    paths = sorted((p for p in root.rglob('*') if p.is_file()),
                   key=lambda p: p.relative_to(root).as_posix().encode('utf-8'))
    for path in paths:
        data = path.read_bytes()
        digest.update(path.relative_to(root).as_posix().encode('utf-8') + b'\0')
        digest.update(len(data).to_bytes(8, 'little'))
        digest.update(data)
    return digest.hexdigest()


def write_checksum(archive):
    """Write `<archive>.sha256` in sha256sum format and return the digest.

    Written as bytes: text mode on a Windows build host would end the line with
    CRLF, and `sha256sum -c` would then look for a file named "<archive>\\r".
    """
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + '.sha256').write_bytes(f'{digest}  {archive.name}\n'.encode('ascii'))
    return digest


def mtime(path):
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return float('inf')  # an input that is gone has changed


def newest_source(root, executable):
    # Cargo's dep-info file next to the executable (<name>.d, one Makefile rule,
    # spaces in paths escaped as "\ ") lists the workspace sources and build
    # script inputs it was built from, but no manifest or lockfile. Add the
    # workspace manifest, Cargo.lock and the manifests of the listed crates.
    # Without a dep-info file, every workspace member counts.
    crates = [root / 'apps/local-web', *(root / 'crates').iterdir()]
    paths = [root / 'Cargo.toml', root / 'Cargo.lock']
    dep_info = executable.with_suffix('.d')
    if dep_info.is_file():
        for line in dep_info.read_text(encoding='utf-8').splitlines():
            deps = line.partition(': ')[2]
            paths += [root / p.replace('\\ ', ' ') for p in re.split(r'(?<!\\) ', deps) if p]
        paths += [crate / 'Cargo.toml' for crate in crates if any(crate in p.parents for p in paths)]
    else:
        for crate in crates:
            paths += [p for p in (crate / 'Cargo.toml', crate / 'build.rs') if p.is_file()]
            paths += (crate / 'src').rglob('*.rs')
    return max(paths, key=mtime)


def require_hardware_policy(info, os_name):
    expected = 'secure-enclave' if os_name == 'macos' else 'tpm2'
    if (info.get('keyProtection') != 'hardware-preferred'
            or info.get('hardwareBackend') != expected
            or info.get('softwareFallback') != 'explicit-approval'):
        raise SystemExit('Packages must prefer hardware and require explicit approval for software fallback.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--configuration', choices=['debug', 'release'], default='release')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    system = platform.system()
    if system not in ['Windows', 'Linux', 'Darwin']:
        raise SystemExit('Unsupported native build host')
    if not args.skip_build:
        if system == 'Windows':
            raise SystemExit('Use package-local-web.ps1 on Windows to load the MSVC build tools.')
        subprocess.run(['npm', 'run', 'web:build'], cwd=root / 'apps/desktop', check=True)
        command = ['cargo', 'build', '--manifest-path', str(root / 'Cargo.toml'), '--locked', '-p', 'najwa-web', '--features', 'bundled-ui']
        if args.configuration == 'release':
            command.append('--release')
        subprocess.run(command, check=True)
    executable = root / 'target' / args.configuration / ('najwa-web.exe' if system == 'Windows' else 'najwa-web')
    newest = newest_source(root, executable)
    if executable.stat().st_mtime < mtime(newest):
        raise SystemExit(f'Executable is older than {newest}; rebuild before packaging.')
    info = json.loads(subprocess.check_output([str(executable), '--build-info'], text=True))
    if info.get('product') != 'Najwa' or info.get('embeddedUi') is not True:
        raise SystemExit('Only a native app with embedded UI can be packaged.')
    os_name = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}[system]
    require_hardware_policy(info, os_name)
    architecture = {'x86_64': 'x64', 'aarch64': 'arm64'}.get(info.get('arch'))
    if info.get('os') != os_name or architecture is None:
        raise SystemExit('Executable does not match this native build host.')
    ui_root = root / 'target/local-web-ui'
    if not (ui_root / 'index.html').is_file() or ui_digest(ui_root) != info.get('uiDigest'):
        raise SystemExit('Embedded UI differs from the current UI build; rebuild the native app.')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    package_name = f'najwa-{os_name}-{architecture}-{args.configuration}-{stamp}'
    directory = root / 'target/packages' / package_name
    directory.mkdir(parents=True, exist_ok=False)
    shutil.copy2(root / 'apps/local-web/package/README.txt', directory / 'README.txt')
    shutil.copy2(root / 'LICENSE', directory / 'LICENSE.txt')
    (directory / 'build-info.json').write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
    if system == 'Windows':
        # Only use the installed Visual Studio redistributable, never an arbitrary
        # DLL from PATH/System32. UCRT and the remaining imports are Windows APIs.
        vswhere = pathlib.Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        installation = pathlib.Path(subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-property', 'installationPath'], text=True).strip())
        candidates = sorted((installation / 'VC/Redist/MSVC').glob(f'*/{architecture}/Microsoft.VC*.CRT/vcruntime140.dll'), reverse=True)
        if not candidates:
            raise SystemExit('Install the Visual Studio C++ runtime redistributable files before packaging.')
        shutil.copy2(candidates[0], directory / 'vcruntime140.dll')
    if system == 'Darwin':
        bundle = directory / 'Najwa.app/Contents'
        (bundle / 'MacOS').mkdir(parents=True)
        shutil.copy2(executable, bundle / 'MacOS/Najwa')
        (bundle / 'MacOS/Najwa').chmod(0o755)
        with (bundle / 'Info.plist').open('wb') as file:
            plistlib.dump({'CFBundleIdentifier': 'org.najwa.web', 'CFBundleName': 'Najwa',
                          'CFBundleDisplayName': 'Najwa', 'CFBundleExecutable': 'Najwa',
                          'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1',
                          'CFBundleShortVersionString': info['version'], 'LSMinimumSystemVersion': '13.0',
                          'LSUIElement': True}, file)
        transport_directory = bundle / 'Resources/transports'
    else:
        transport_directory = directory / 'transports'
        binary = directory / ('Najwa.exe' if system == 'Windows' else 'Najwa')
        shutil.copy2(executable, binary)
        binary.chmod(0o755)
    spec = importlib.util.spec_from_file_location('tor_transports', root / 'scripts/fetch-tor-transports.py')
    transports = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transports)
    transports.fetch(root, f"{os_name}-{info['arch']}", transport_directory)
    if system == 'Darwin':
        # Local execution validation is separate from Developer ID signing/notarization.
        subprocess.run(['codesign', '--force', '--sign', '-', str(bundle.parent)], check=True)
    if system == 'Linux':
        archive = directory.with_suffix('.tar.gz')
        with tarfile.open(archive, 'w:gz') as file:
            file.add(directory, arcname=directory.name)
    else:
        archive = directory.with_suffix('.zip')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as file:
            for path in sorted(directory.rglob('*')):
                file.write(path, path.relative_to(directory.parent))
    digest = write_checksum(archive)
    print(json.dumps({'archive': str(archive), 'directory': str(directory), 'sha256': digest, 'bytes': archive.stat().st_size}))


if __name__ == '__main__':
    main()
