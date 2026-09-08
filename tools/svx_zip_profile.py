#!/usr/bin/env python3
"""Strict, fail-closed ZIP structure validation for SVX release artifacts."""

from __future__ import annotations

from dataclasses import dataclass
import binascii
import io
import struct
from typing import BinaryIO, Iterable
import zlib


LOCAL_SIGNATURE = b"PK\x03\x04"
CENTRAL_SIGNATURE = b"PK\x01\x02"
EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"

LOCAL_HEADER = struct.Struct("<4s5H3I2H")
CENTRAL_HEADER = struct.Struct("<4s6H3I5H2I")
EOCD = struct.Struct("<4s4H2IH")

ZIP64_EXTRA_ID = 0x0001
NTFS_EXTRA_ID = 0x000A
EXTENDED_TIMESTAMP_EXTRA_ID = 0x5455
UNIX_UID_GID_EXTRA_ID = 0x7875

SUPPORTED_METHODS = {0, 8}
STREAM_BUFFER_BYTES = 1024 * 1024
UTF8_FLAG = 0x0800
DEFLATE_OPTION_FLAGS = 0x0006
LZMA_EOS_FLAG = 0x0002
DATA_DESCRIPTOR_FLAG = 0x0008
ENCRYPTED_FLAG = 0x0001


class ZipProfileError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ZipProfileRecord:
    filename_bytes: bytes
    filename: str
    version_needed: int
    flags: int
    method: int
    modified_time: int
    modified_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    data_offset: int
    local_end: int
    central_extra: bytes
    local_extra: bytes


@dataclass(frozen=True)
class ValidatedZipProfile:
    records: tuple[ZipProfileRecord, ...]
    central_offset: int
    central_size: int
    eocd_offset: int

    @property
    def extra_fields(self) -> Iterable[tuple[str, bytes]]:
        for record in self.records:
            if record.central_extra:
                yield f"{record.filename}:central", record.central_extra
            if record.local_extra:
                yield f"{record.filename}:local", record.local_extra


def _read_at(stream: BinaryIO, offset: int, size: int, code: str) -> bytes:
    if offset < 0 or size < 0:
        raise ZipProfileError(code)
    stream.seek(offset)
    value = stream.read(size)
    if len(value) != size:
        raise ZipProfileError(code)
    return value


def _decode_filename(raw: bytes, flags: int) -> str:
    if not raw or b"\x00" in raw:
        raise ZipProfileError("archive-filename-invalid")
    encoding = "utf-8" if flags & UTF8_FLAG else "cp437"
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ZipProfileError("archive-filename-invalid") from exc


def _validate_flags(method: int, flags: int) -> None:
    if flags & ENCRYPTED_FLAG:
        raise ZipProfileError("archive-encrypted-member")
    if flags & DATA_DESCRIPTOR_FLAG:
        raise ZipProfileError("archive-data-descriptor-unsupported")
    allowed = UTF8_FLAG
    if method == 8:
        allowed |= DEFLATE_OPTION_FLAGS
    elif method == 14:
        allowed |= LZMA_EOS_FLAG
    if flags & ~allowed:
        raise ZipProfileError("archive-flags-unsupported")


def _validate_extended_timestamp(data: bytes) -> None:
    if not data:
        raise ZipProfileError("archive-extra-field-invalid")
    flags = data[0]
    if flags & ~0x07:
        raise ZipProfileError("archive-extra-field-invalid")
    if len(data) != 1 + 4 * bin(flags).count("1"):
        raise ZipProfileError("archive-extra-field-invalid")


def _validate_unix_uid_gid(data: bytes) -> None:
    if len(data) < 4 or data[0] != 1:
        raise ZipProfileError("archive-extra-field-invalid")
    uid_size = data[1]
    if uid_size < 1 or uid_size > 8 or 2 + uid_size >= len(data):
        raise ZipProfileError("archive-extra-field-invalid")
    gid_size_offset = 2 + uid_size
    gid_size = data[gid_size_offset]
    if gid_size < 1 or gid_size > 8 or gid_size_offset + 1 + gid_size != len(data):
        raise ZipProfileError("archive-extra-field-invalid")


def _validate_ntfs(data: bytes) -> None:
    if len(data) != 32 or data[:4] != b"\x00\x00\x00\x00":
        raise ZipProfileError("archive-extra-field-invalid")
    tag, size = struct.unpack_from("<HH", data, 4)
    if tag != 1 or size != 24:
        raise ZipProfileError("archive-extra-field-invalid")


def validate_extra_fields(raw: bytes, allowed_ids: set[int]) -> None:
    offset = 0
    seen: set[int] = set()
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise ZipProfileError("archive-extra-field-malformed")
        identifier, size = struct.unpack_from("<HH", raw, offset)
        offset += 4
        if size > len(raw) - offset or identifier in seen:
            raise ZipProfileError("archive-extra-field-malformed")
        seen.add(identifier)
        data = raw[offset : offset + size]
        offset += size
        if identifier == ZIP64_EXTRA_ID:
            raise ZipProfileError("archive-zip64-unsupported")
        if identifier not in allowed_ids:
            raise ZipProfileError("archive-extra-field-unsupported")
        if identifier == EXTENDED_TIMESTAMP_EXTRA_ID:
            _validate_extended_timestamp(data)
        elif identifier == UNIX_UID_GID_EXTRA_ID:
            _validate_unix_uid_gid(data)
        elif identifier == NTFS_EXTRA_ID:
            _validate_ntfs(data)
        else:
            raise ZipProfileError("archive-extra-field-unsupported")


def _update_output_identity(
    output: bytes,
    output_size: int,
    crc32: int,
    declared_size: int,
    maximum_size: int | None,
) -> tuple[int, int]:
    output_size += len(output)
    if output_size > declared_size or (maximum_size is not None and output_size > maximum_size):
        raise ZipProfileError("archive-member-size")
    return output_size, binascii.crc32(output, crc32) & 0xFFFFFFFF


def _validate_compressed_stream(
    stream: BinaryIO,
    record: ZipProfileRecord,
    maximum_size: int | None,
) -> None:
    if maximum_size is not None and record.uncompressed_size > maximum_size:
        raise ZipProfileError("archive-member-size")
    stream.seek(record.data_offset)
    remaining = record.compressed_size
    output_size = 0
    crc32 = 0

    if record.method == 0:
        if record.compressed_size != record.uncompressed_size:
            raise ZipProfileError("archive-stored-size-mismatch")
        while remaining:
            chunk = stream.read(min(STREAM_BUFFER_BYTES, remaining))
            if not chunk:
                raise ZipProfileError("archive-compressed-stream-truncated")
            remaining -= len(chunk)
            output_size, crc32 = _update_output_identity(
                chunk,
                output_size,
                crc32,
                record.uncompressed_size,
                maximum_size,
            )
    else:
        decoder = zlib.decompressobj(-15)
        try:
            while remaining:
                chunk = stream.read(min(STREAM_BUFFER_BYTES, remaining))
                if not chunk:
                    raise ZipProfileError("archive-compressed-stream-truncated")
                remaining -= len(chunk)
                pending = chunk
                while True:
                    output = decoder.decompress(pending, STREAM_BUFFER_BYTES)
                    pending = decoder.unconsumed_tail
                    output_size, crc32 = _update_output_identity(
                        output,
                        output_size,
                        crc32,
                        record.uncompressed_size,
                        maximum_size,
                    )
                    if decoder.eof:
                        if decoder.unused_data or pending or remaining:
                            raise ZipProfileError("archive-compressed-stream-trailing-data")
                        break
                    if pending or len(output) == STREAM_BUFFER_BYTES:
                        continue
                    if not output:
                        break
                    break
        except zlib.error as exc:
            raise ZipProfileError("archive-compressed-stream-invalid") from exc
        if not decoder.eof:
            raise ZipProfileError("archive-compressed-stream-truncated")
        if decoder.unused_data or decoder.unconsumed_tail:
            raise ZipProfileError("archive-compressed-stream-trailing-data")

    if output_size != record.uncompressed_size or crc32 != record.crc32:
        raise ZipProfileError("archive-compressed-stream-identity-mismatch")


def validate_zip_profile(
    source: bytes | bytearray | memoryview | BinaryIO,
    size: int | None,
    allowed_extra_field_ids: set[int],
    maximum_member_uncompressed_bytes: int | None = None,
    maximum_total_uncompressed_bytes: int | None = None,
) -> ValidatedZipProfile:
    owned_stream: io.BytesIO | None = None
    if isinstance(source, (bytes, bytearray, memoryview)):
        payload = bytes(source)
        owned_stream = io.BytesIO(payload)
        stream: BinaryIO = owned_stream
        actual_size = len(payload)
    else:
        stream = source
        if size is None:
            current = stream.tell()
            stream.seek(0, io.SEEK_END)
            actual_size = stream.tell()
            stream.seek(current)
        else:
            actual_size = size

    if actual_size < EOCD.size:
        raise ZipProfileError("archive-eocd-not-at-eof")
    eocd_offset = actual_size - EOCD.size
    eocd_raw = _read_at(stream, eocd_offset, EOCD.size, "archive-eocd-not-at-eof")
    (
        signature,
        disk_number,
        central_disk,
        entries_on_disk,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = EOCD.unpack(eocd_raw)
    if signature != EOCD_SIGNATURE or comment_length != 0:
        raise ZipProfileError("archive-eocd-not-at-eof")
    if eocd_offset >= 20 and _read_at(
        stream,
        eocd_offset - 20,
        4,
        "archive-eocd-not-at-eof",
    ) == ZIP64_LOCATOR_SIGNATURE:
        raise ZipProfileError("archive-zip64-unsupported")
    if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
        raise ZipProfileError("archive-multidisk-unsupported")
    if (
        entries_on_disk == 0xFFFF
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise ZipProfileError("archive-zip64-unsupported")
    if central_offset + central_size != eocd_offset:
        raise ZipProfileError("archive-central-boundary-invalid")
    if total_entries == 0:
        if central_offset != 0 or central_size != 0 or eocd_offset != 0:
            raise ZipProfileError("archive-empty-boundary-invalid")
        return ValidatedZipProfile((), 0, 0, 0)

    records: list[ZipProfileRecord] = []
    central_cursor = central_offset
    central_end = central_offset + central_size
    local_offsets: set[int] = set()
    for _ in range(total_entries):
        header = _read_at(stream, central_cursor, CENTRAL_HEADER.size, "archive-central-truncated")
        values = CENTRAL_HEADER.unpack(header)
        if values[0] != CENTRAL_SIGNATURE:
            if values[0] in {ZIP64_EOCD_SIGNATURE, ZIP64_LOCATOR_SIGNATURE}:
                raise ZipProfileError("archive-zip64-unsupported")
            raise ZipProfileError("archive-central-signature-invalid")
        (
            _,
            _version_made,
            version_needed,
            flags,
            method,
            modified_time,
            modified_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_length,
            member_comment_length,
            member_disk,
            _internal_attributes,
            _external_attributes,
            local_offset,
        ) = values
        if method not in SUPPORTED_METHODS:
            raise ZipProfileError("archive-compression-unsupported")
        _validate_flags(method, flags)
        if member_comment_length:
            raise ZipProfileError("archive-member-comment-unsupported")
        if member_disk != 0:
            raise ZipProfileError("archive-multidisk-unsupported")
        if (
            compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or local_offset == 0xFFFFFFFF
        ):
            raise ZipProfileError("archive-zip64-unsupported")
        if local_offset in local_offsets:
            raise ZipProfileError("archive-local-offset-duplicate")
        local_offsets.add(local_offset)
        variable_size = filename_length + extra_length + member_comment_length
        variable = _read_at(
            stream,
            central_cursor + CENTRAL_HEADER.size,
            variable_size,
            "archive-central-truncated",
        )
        filename_bytes = variable[:filename_length]
        central_extra = variable[filename_length : filename_length + extra_length]
        filename = _decode_filename(filename_bytes, flags)
        validate_extra_fields(central_extra, allowed_extra_field_ids)
        central_cursor += CENTRAL_HEADER.size + variable_size
        if central_cursor > central_end:
            raise ZipProfileError("archive-central-boundary-invalid")

        local_header = _read_at(stream, local_offset, LOCAL_HEADER.size, "archive-local-truncated")
        local_values = LOCAL_HEADER.unpack(local_header)
        if local_values[0] != LOCAL_SIGNATURE:
            raise ZipProfileError("archive-local-signature-invalid")
        (
            _,
            local_version_needed,
            local_flags,
            local_method,
            local_time,
            local_date,
            local_crc32,
            local_compressed_size,
            local_uncompressed_size,
            local_filename_length,
            local_extra_length,
        ) = local_values
        if (
            local_version_needed != version_needed
            or local_flags != flags
            or local_method != method
            or local_time != modified_time
            or local_date != modified_date
            or local_crc32 != crc32
            or local_compressed_size != compressed_size
            or local_uncompressed_size != uncompressed_size
            or local_filename_length != filename_length
        ):
            raise ZipProfileError("archive-local-central-mismatch")
        local_variable = _read_at(
            stream,
            local_offset + LOCAL_HEADER.size,
            local_filename_length + local_extra_length,
            "archive-local-truncated",
        )
        local_filename = local_variable[:local_filename_length]
        local_extra = local_variable[local_filename_length:]
        if local_filename != filename_bytes:
            raise ZipProfileError("archive-local-central-mismatch")
        validate_extra_fields(local_extra, allowed_extra_field_ids)
        data_offset = local_offset + LOCAL_HEADER.size + local_filename_length + local_extra_length
        local_end = data_offset + compressed_size
        if local_end > central_offset:
            raise ZipProfileError("archive-local-boundary-invalid")
        records.append(
            ZipProfileRecord(
                filename_bytes=filename_bytes,
                filename=filename,
                version_needed=version_needed,
                flags=flags,
                method=method,
                modified_time=modified_time,
                modified_date=modified_date,
                crc32=crc32,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_offset=local_offset,
                data_offset=data_offset,
                local_end=local_end,
                central_extra=central_extra,
                local_extra=local_extra,
            )
        )

    if central_cursor != central_end:
        raise ZipProfileError("archive-central-boundary-invalid")
    cursor = 0
    for record in sorted(records, key=lambda item: item.local_offset):
        if record.local_offset != cursor:
            category = "archive-local-overlap" if record.local_offset < cursor else "archive-unattributed-bytes"
            raise ZipProfileError(category)
        cursor = record.local_end
    if cursor != central_offset:
        raise ZipProfileError("archive-unattributed-bytes")
    total_uncompressed = sum(record.uncompressed_size for record in records)
    if (
        maximum_total_uncompressed_bytes is not None
        and total_uncompressed > maximum_total_uncompressed_bytes
    ):
        raise ZipProfileError("archive-total-size")
    for record in records:
        _validate_compressed_stream(stream, record, maximum_member_uncompressed_bytes)
    return ValidatedZipProfile(tuple(records), central_offset, central_size, eocd_offset)
