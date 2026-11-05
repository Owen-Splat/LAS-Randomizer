"""Fetch the pinned upstream dev runtime; do not replace modified local files."""
import hashlib
from pathlib import Path
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'd7d76a89f0acf1657df3f2737c1d9780e5a14bef'
FILES = {
    'main.npdm': '60ca159313194044a48d5f40e4829b0ce8239fd923a7a5c0921d507f2a95cfb8',
    'subsdk9': 'c06c9c9eea64b5e55dfb363294159051bc76da1893f4213c60124bd2f98277fd',
}

def main():
    target = ROOT/'exl'
    target.mkdir(parents=True, exist_ok=True)
    for name, expected in FILES.items():
        path = target/name
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f'{path} differs from the pinned runtime; move it aside before retrying.')
        else:
            url = f'https://raw.githubusercontent.com/Owen-Splat/DEV-BUILD-LASR/{REVISION}/exl/{name}'
            with urlopen(url, timeout=30) as response:
                contents = response.read()
            if hashlib.sha256(contents).hexdigest() != expected:
                raise ValueError(f'Unexpected download hash for {name}')
            path.write_bytes(contents)
        print(f'Verified {path}')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
