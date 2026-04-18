"""Makes `python -m fourdollarvpn` work the same as the `fourdollarvpn` entry point.

Uses the absolute import path (`fourdollarvpn.cli`) so this module also works
as a PyInstaller entry point — `--onefile` runs this file as a bare script
rather than as part of the package, which breaks relative imports.
"""
from fourdollarvpn.cli import main

if __name__ == "__main__":
    main()
