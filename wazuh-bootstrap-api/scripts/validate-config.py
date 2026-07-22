#!/usr/bin/env python3
"""Validate an environment file without printing values or secrets."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pydantic import ValidationError

# Executing this file by absolute path makes Python expose only the scripts/
# directory on sys.path. Add the application root so the validator works from
# any current working directory, including during a production installation.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def decode_env_value(raw_value: str, line_number: int) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    if value[0] not in {'"', "'"}:
        return value

    quote = value[0]
    if len(value) < 2 or value[-1] != quote:
        raise ValueError(f"unterminated quoted value at line {line_number}")
    inner = value[1:-1]
    if quote == "'":
        if quote in inner:
            raise ValueError(f"unexpected quote at line {line_number}")
        return inner

    decoded: list[str] = []
    index = 0
    while index < len(inner):
        character = inner[index]
        if character == '"':
            raise ValueError(f"unexpected quote at line {line_number}")
        if character == "\\":
            index += 1
            if index >= len(inner):
                raise ValueError(f"unterminated escape at line {line_number}")
            character = inner[index]
        decoded.append(character)
        index += 1
    return "".join(decoded)


def load_env(path: Path) -> None:
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid env syntax at line {number}")
        key, value = line.split("=", 1)
        if not key or any(char.isspace() for char in key):
            raise ValueError(f"invalid env key at line {number}")
        os.environ[key] = decode_env_value(value, number)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--import-app", action="store_true", help="also build the FastAPI app")
    args = parser.parse_args()
    try:
        load_env(args.env_file)
        from app.core.config import Settings

        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        if args.import_app:
            from app.main import create_app

            create_app(settings)
    except ValidationError as exc:
        print("Configuration validation failed:")
        for error in exc.errors(include_input=False, include_url=False):
            location = ".".join(str(item) for item in error["loc"])
            print(f"- {location}: {error['msg']}")
        return 1
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}")
        return 1
    print("Configuration is valid (secret values were not displayed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
