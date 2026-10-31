"""Bounds-checked structural parser for thin Mach-O files.

This module reports file structure only. It does not execute files, validate
Apple trust, or attempt to alter or bypass code-signing enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Final


class MachOError(ValueError):
    """Raised when a Mach-O or embedded signature structure is malformed."""


_MAGICS: Final = {
    b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xfe\xed\xfa\xce": (">", 32),
    b"\xcf\xfa\xed\xfe": ("<", 64),
    b"\xfe\xed\xfa\xcf": (">", 64),
}
_LC_CODE_SIGNATURE: Final = 0x1D
_LC_REQ_DYLD: Final = 0x80000000
_CSMAGIC_EMBEDDED_SIGNATURE: Final = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY: Final = 0xFADE0C02


@dataclass(frozen=True)
class MachOHeader:
    byte_order: str
    bits: int
    cpu_type: int
    cpu_subtype: int
    file_type: int
    command_count: int
    command_bytes: int
    flags: int


@dataclass(frozen=True)
class SignatureInfo:
    data_offset: int
    data_size: int
    magic: int
    length: int
    blob_count: int
    code_directories: int


@dataclass(frozen=True)
class MachOInfo:
    header: MachOHeader
    signature: SignatureInfo | None


def _require(data: bytes, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise MachOError(f"{what} is outside the file")


def _u32(data: bytes, offset: int, order: str, what: str) -> int:
    _require(data, offset, 4, what)
    return struct.unpack_from(order + "I", data, offset)[0]


def parse_signature(data: bytes, offset: int, size: int, order: str = ">") -> SignatureInfo:
    """Inspect an embedded Apple SuperBlob and count CodeDirectory entries."""
    _require(data, offset, size, "code-signature region")
    if size < 12:
        raise MachOError("code-signature SuperBlob is shorter than its header")

    magic = _u32(data, offset, order, "SuperBlob magic")
    length = _u32(data, offset + 4, order, "SuperBlob length")
    count = _u32(data, offset + 8, order, "SuperBlob count")

    if magic != _CSMAGIC_EMBEDDED_SIGNATURE:
        raise MachOError(f"unexpected signature blob magic: 0x{magic:08x}")
    if length < 12 or length > size:
        raise MachOError("SuperBlob length is inconsistent with its region")
    if count > (length - 12) // 8:
        raise MachOError("SuperBlob index table exceeds declared length")

    code_directories = 0
    for index in range(count):
        entry = offset + 12 + index * 8
        blob_type = _u32(data, entry, order, "SuperBlob index type")
        blob_offset = _u32(data, entry + 4, order, "SuperBlob index offset")
        if blob_offset > length - 8:
            raise MachOError("embedded blob offset is outside SuperBlob")
        blob_magic = _u32(data, offset + blob_offset, order, "embedded blob magic")
        blob_length = _u32(data, offset + blob_offset + 4, order, "embedded blob length")
        if blob_length < 8 or blob_length > length - blob_offset:
            raise MachOError("embedded blob length is invalid")
        if blob_type == 0 and blob_magic == _CSMAGIC_CODEDIRECTORY:
            code_directories += 1

    return SignatureInfo(offset, size, magic, length, count, code_directories)


def inspect_macho(data: bytes) -> MachOInfo:
    """Parse a thin Mach-O header and locate an optional code signature."""
    if len(data) < 4:
        raise MachOError("file is too short to contain a Mach-O magic")
    try:
        order, bits = _MAGICS[data[:4]]
    except KeyError as exc:
        raise MachOError("unsupported magic: expected a thin Mach-O file") from exc

    header_size = 28 if bits == 32 else 32
    _require(data, 0, header_size, "Mach-O header")
    fields = struct.unpack_from(order + ("IiiIIII" if bits == 32 else "IiiIIIII"), data, 0)
    _, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags, *_ = fields

    if ncmds > sizeofcmds // 8:
        raise MachOError("load-command count cannot fit in declared command bytes")
    commands_start = header_size
    commands_end = commands_start + sizeofcmds
    _require(data, commands_start, sizeofcmds, "load-command region")

    header = MachOHeader(order, bits, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags)
    cursor = commands_start
    signature_command: tuple[int, int] | None = None

    for _ in range(ncmds):
        if cursor + 8 > commands_end:
            raise MachOError("truncated load command")
        cmd = _u32(data, cursor, order, "load command")
        cmdsize = _u32(data, cursor + 4, order, "load-command size")
        if cmdsize < 8 or cmdsize > commands_end - cursor:
            raise MachOError("invalid load-command size")
        if (cmd & ~_LC_REQ_DYLD) == _LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise MachOError("LC_CODE_SIGNATURE is shorter than 16 bytes")
            if signature_command is not None:
                raise MachOError("multiple LC_CODE_SIGNATURE commands are not supported")
            dataoff = _u32(data, cursor + 8, order, "signature data offset")
            datasize = _u32(data, cursor + 12, order, "signature data size")
            signature_command = (dataoff, datasize)
        cursor += cmdsize

    if cursor != commands_end:
        raise MachOError("load commands do not consume sizeofcmds exactly")

    signature = None
    if signature_command is not None:
        dataoff, datasize = signature_command
        signature = parse_signature(data, dataoff, datasize, order=">")
    return MachOInfo(header, signature)
