"""Command-line entry point for static Mach-O inspection."""

import argparse
import hashlib
from pathlib import Path
import sys

from .macho import MachOError, inspect_macho


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect Mach-O structure and embedded signature metadata (read-only)."
    )
    parser.add_argument("file", type=Path, help="path to a Mach-O file to inspect")
    args = parser.parse_args()

    try:
        data = args.file.read_bytes()
        info = inspect_macho(data)
    except (OSError, MachOError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"File: {args.file}")
    print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
    print(f"Format: thin Mach-O {info.header.bits}-bit ({'little' if info.header.byte_order == '<' else 'big'} endian)")
    print(f"CPU type: {info.header.cpu_type}")
    print(f"CPU subtype: {info.header.cpu_subtype}")
    print(f"File type: {info.header.file_type}")
    print(f"Load commands: {info.header.command_count}")
    if info.signature is None:
        print("Embedded code signature: not found")
    else:
        sig = info.signature
        print(f"Embedded code signature: offset={sig.data_offset}, size={sig.data_size}")
        print(f"SuperBlob length: {sig.length}")
        print(f"Indexed blobs: {sig.blob_count}")
        print(f"CodeDirectory entries: {sig.code_directories}")
    print("Note: structural parsing is not Apple trust validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
