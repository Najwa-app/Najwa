"""Build-time only: fetch a pinned Tor Project Lyrebird and its license notices.

Archive checksums were verified against Tor Browser Developers' signed 15.0.26
checksum file. Never execute an archive member or extract arbitrary archive paths.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import tarfile
import urllib.request


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def fetch(root, platform, destination):
    manifest = json.loads((root / 'tor-transports.json').read_text())
    entry = manifest['platforms'][platform]
    cache = root / 'target/tor-upstream-verification'
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / entry['archive']
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        try:
            urllib.request.urlretrieve(manifest['source'] + entry['archive'], temporary)
            if digest(temporary) != entry['archiveSha256']:
                raise ValueError('Tor archive checksum mismatch')
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    if digest(archive) != entry['archiveSha256']:
        raise ValueError('Tor archive checksum mismatch')
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as bundle:
        for kind, name in [('binary', 'lyrebird.exe' if platform.startswith('windows-') else 'lyrebird'),
                           ('license', 'LYREBIRD-LICENSES.txt')]:
            member = bundle.getmember(entry[kind + 'Member'])
            if not member.isfile() or member.size > 32 * 1024 * 1024:
                raise ValueError('Unexpected Tor archive member')
            target = destination / name
            with bundle.extractfile(member) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
            if digest(target) != entry[kind + 'Sha256']:
                target.unlink()
                raise ValueError('Tor archive member checksum mismatch')
            target.chmod(0o755 if kind == 'binary' else 0o644)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', required=True)
    parser.add_argument('--destination', type=pathlib.Path, required=True)
    args = parser.parse_args()
    fetch(pathlib.Path(__file__).resolve().parents[1], args.platform, args.destination)
