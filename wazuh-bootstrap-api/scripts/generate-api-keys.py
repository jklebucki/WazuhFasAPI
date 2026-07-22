#!/usr/bin/env python3
"""Generate independent API keys without persisting them unless requested."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path


def generate() -> str:
    client = secrets.token_urlsafe(48)
    admin = secrets.token_urlsafe(48)
    while secrets.compare_digest(client, admin):
        admin = secrets.token_urlsafe(48)
    return f"CLIENT_API_KEY={client}\nADMIN_API_KEY={admin}\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", type=Path, help="write keys to a new or replaced mode-0600 file")
    args = parser.parse_args()
    output = generate()
    if args.write:
        descriptor = os.open(args.write, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, output.encode())
        finally:
            os.close(descriptor)
        os.chmod(args.write, 0o600)
        print(f"API keys written to {args.write} with mode 0600")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
