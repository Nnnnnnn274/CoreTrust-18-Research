import struct

import pytest

from coretrust_research.macho import MachOError, inspect_macho, parse_signature


def make_macho(signature: bool = True) -> bytes:
    # Minimal little-endian 64-bit Mach-O and optional synthetic signature.
    if not signature:
        return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)

    command = struct.pack("<IIII", 0x1D, 16, 48, 28)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    superblob = struct.pack(">III", 0xFADE0CC0, 28, 1)
    superblob += struct.pack(">II", 0, 20)
    superblob += struct.pack(">II", 0xFADE0C02, 8)
    return header + command + superblob


def test_parses_64_bit_macho_and_signature():
    info = inspect_macho(make_macho())
    assert info.header.bits == 64
    assert info.header.cpu_type == 0x0100000C
    assert info.header.command_count == 1
    assert info.signature is not None
    assert info.signature.blob_count == 1
    assert info.signature.code_directories == 1


def test_parses_macho_without_signature():
    info = inspect_macho(make_macho(signature=False))
    assert info.signature is None


def test_rejects_unknown_magic():
    with pytest.raises(MachOError, match="unsupported magic"):
        inspect_macho(b"nope" + bytes(40))


def test_rejects_truncated_header():
    with pytest.raises(MachOError):
        inspect_macho(b"\xcf\xfa\xed\xfe")


def test_rejects_invalid_superblob():
    with pytest.raises(MachOError):
        parse_signature(struct.pack(">III", 0, 12, 0), 0, 12)


def test_rejects_truncated_load_command():
    data = struct.pack("<IiiIIIII", 0xFEEDFACF, 0, 0, 2, 1, 8, 0, 0) + struct.pack("<II", 1, 4)
    with pytest.raises(MachOError):
        inspect_macho(data)
