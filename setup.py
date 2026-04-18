import pathlib
import re

from setuptools import find_packages, setup

_init = pathlib.Path(__file__).parent / "fourdollarvpn" / "__init__.py"
_match = re.search(
    r'^__version__ = "([^"]+)"', _init.read_text(encoding="utf-8"), re.MULTILINE
)
if not _match:
    raise RuntimeError("Could not find __version__ in fourdollarvpn/__init__.py")
version = _match.group(1)

setup(
    name="fourdollarvpn",
    version=version,
    packages=find_packages(),
    install_requires=[
        "requests>=2.32.4",
        "paramiko>=3.4.0",
        "rich>=13.7.0",
        "cryptography>=42.0.0",
        "qrcode>=7.4.0",
    ],
    entry_points={
        "console_scripts": [
            "fourdollarvpn=fourdollarvpn.cli:main",
        ],
    },
    python_requires=">=3.9",
)
