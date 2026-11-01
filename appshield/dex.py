"""
AppShield DEX Inspector and Parser.
Provides robust, defensive parsing of Dalvik Executable (DEX) headers, string identifier tables,
and class definitions across single-dex and multidex APK archives.
Treats all input binary data as untrusted with strict offset and size bounds validation.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# DEX format constants
DEX_MAGIC = b"dex\n"
DEX_HEADER_SIZE = 112  # 0x70 bytes

# Standard Dalvik Executable versions supported by the AGP 8.2 / Android API 34 toolchain:
# 035: Android 1.0 - 6.0
# 037: Android 7.0 (Nougat)
# 038: Android 8.0 (Oreo)
# 039: Android 9.0 (Pie)
# 040: Android 10+ (API 29-34)
SUPPORTED_DEX_VERSIONS = {"035\0", "037\0", "038\0", "039\0", "040\0"}

# DEX version 041 (Android 15+ Container DEX) is explicitly UNSUPPORTED in the current release.
# Container DEX uses an altered header and container layout; it must not be parsed using the 112-byte header.
UNSUPPORTED_CONTAINER_DEX_VERSIONS = {"041\0"}
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412

# Safety limits to defend against resource exhaustion from malformed inputs
MAX_DEX_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB per DEX file
MAX_STRINGS_COUNT = 500_000
MAX_CLASSES_COUNT = 100_000
MAX_STRING_LENGTH_BYTES = 65_536  # 64 KB per string constant


class DexError(Exception):
    """Base exception for all DEX parsing and inspection errors."""


class DexParseError(DexError):
    """Raised when DEX binary data is malformed, truncated, or exceeds safety bounds."""


class DexVersionError(DexParseError):
    """Raised when the DEX magic or version identifier is unsupported."""


@dataclass(frozen=True)
class DexHeader:
    """Structured header data from a Dalvik Executable file."""

    magic: bytes
    version: str
    checksum: int
    signature: bytes
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int

    @property
    def is_little_endian(self) -> bool:
        return self.endian_tag == ENDIAN_CONSTANT


@dataclass(frozen=True)
class DexFileInfo:
    """Inspection summary of an individual DEX file."""

    name: str
    header: DexHeader
    classes_count: int
    strings_count: int
    class_descriptors: list[str]
    strings: list[str]


@dataclass(frozen=True)
class ApkDexSummary:
    """Aggregate DEX inspection summary across all DEX files in an APK archive."""

    dex_files_count: int
    dex_names: list[str]
    total_classes_count: int
    total_strings_count: int
    unique_class_descriptors: list[str]
    unique_strings: list[str]
    dex_files: list[DexFileInfo]
    errors: list[str] = field(default_factory=list)


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode an unsigned LEB128 (Little-Endian Base 128) integer from binary data.
    Enforces a strict 5-byte maximum to prevent infinite loops on malformed streams.

    Returns:
        (decoded_value, next_offset)
    """
    result = 0
    shift = 0
    pos = offset
    data_len = len(data)

    for _ in range(5):
        if pos >= data_len:
            raise DexParseError(
                f"Unexpected end of file while reading ULEB128 at offset {offset}"
            )
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7

    raise DexParseError(
        f"Malformed ULEB128 sequence exceeding 5 bytes at offset {offset}"
    )


def encode_uleb128(value: int) -> bytes:
    """Helper to encode a non-negative integer as ULEB128."""
    if value == 0:
        return b"\x00"
    out = bytearray()
    val = value
    while val > 0:
        byte = val & 0x7F
        val >>= 7
        if val > 0:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def parse_dex_header(data: bytes) -> DexHeader:
    """
    Parse and validate a 112-byte DEX file header with defensive sanity checks.
    """
    if len(data) < DEX_HEADER_SIZE:
        raise DexParseError(
            f"DEX data is too small to contain a valid header: {len(data)} bytes (minimum {DEX_HEADER_SIZE})"
        )

    # Magic check: 4 bytes 'dex\n'
    magic_prefix = data[:4]
    if magic_prefix != DEX_MAGIC:
        raise DexVersionError(
            f"Invalid DEX magic prefix: expected {DEX_MAGIC!r}, got {magic_prefix!r}"
        )

    # Version check: 4 bytes (e.g. '035\0')
    version_raw = data[4:8]
    try:
        version_str = version_raw.decode("ascii")
    except UnicodeDecodeError:
        version_str = repr(version_raw)

    if version_str in UNSUPPORTED_CONTAINER_DEX_VERSIONS or version_str == "041\0":
        raise DexVersionError(
            f"Unsupported DEX version {version_str!r} (Container DEX format): "
            "DEX version 041 is unsupported in the current AppShield release. "
            "AppShield MVP targets standard DEX versions 035-040 generated by the supported AGP 8.2 / API 34 toolchain. "
            "Container DEX uses an altered container header layout and must not be parsed using legacy 112-byte headers."
        )

    if version_str not in SUPPORTED_DEX_VERSIONS:
        raise DexVersionError(
            f"Unsupported DEX version: {version_str!r}. Supported versions: {sorted(SUPPORTED_DEX_VERSIONS)}"
        )

    # Unpack header fields (little endian)
    # Total: 8s (8) + I (4) + 20s (20) + 20 * I (80) = 112 bytes
    header_fmt = "<8sI20s" + "I" * 20
    try:
        fields = struct.unpack(header_fmt, data[:DEX_HEADER_SIZE])
    except struct.error as e:
        raise DexParseError(f"Failed to unpack DEX header: {e}") from e

    (
        magic,
        checksum,
        signature,
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = fields

    # Endianness validation
    if endian_tag != ENDIAN_CONSTANT:
        if endian_tag == REVERSE_ENDIAN_CONSTANT:
            raise DexParseError(
                "Big-endian DEX files are not supported in standard Android runtime."
            )
        raise DexParseError(
            f"Invalid DEX endian tag: expected 0x{ENDIAN_CONSTANT:08x}, got 0x{endian_tag:08x}"
        )

    # Header size validation
    if header_size != DEX_HEADER_SIZE:
        raise DexParseError(
            f"Invalid DEX header size: expected {DEX_HEADER_SIZE}, got {header_size}"
        )

    # File size validation
    actual_len = len(data)
    if actual_len > MAX_DEX_SIZE_BYTES:
        raise DexParseError(
            f"DEX size ({actual_len} bytes) exceeds safety limit ({MAX_DEX_SIZE_BYTES} bytes)"
        )
    if file_size > actual_len:
        raise DexParseError(
            f"Truncated DEX file: header declares file_size={file_size}, actual size={actual_len}"
        )

    # Count safety validation
    if string_ids_size > MAX_STRINGS_COUNT:
        raise DexParseError(
            f"String count ({string_ids_size}) exceeds safety limit ({MAX_STRINGS_COUNT})"
        )
    if class_defs_size > MAX_CLASSES_COUNT:
        raise DexParseError(
            f"Class count ({class_defs_size}) exceeds safety limit ({MAX_CLASSES_COUNT})"
        )

    return DexHeader(
        magic=magic,
        version=version_str,
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        link_size=link_size,
        link_off=link_off,
        map_off=map_off,
        string_ids_size=string_ids_size,
        string_ids_off=string_ids_off,
        type_ids_size=type_ids_size,
        type_ids_off=type_ids_off,
        proto_ids_size=proto_ids_size,
        proto_ids_off=proto_ids_off,
        field_ids_size=field_ids_size,
        field_ids_off=field_ids_off,
        method_ids_size=method_ids_size,
        method_ids_off=method_ids_off,
        class_defs_size=class_defs_size,
        class_defs_off=class_defs_off,
        data_size=data_size,
        data_off=data_off,
    )


def extract_dex_strings(data: bytes, header: DexHeader) -> list[str]:
    """
    Extract all string constants from the DEX string identifier table.
    Enforces offset bounds and null-termination limits.
    """
    count = header.string_ids_size
    table_off = header.string_ids_off
    data_len = len(data)

    # Validate string_ids table bounds
    table_bytes_needed = count * 4
    if table_off + table_bytes_needed > data_len:
        raise DexParseError(
            f"string_ids table out of bounds: offset {table_off} + {table_bytes_needed} bytes > file size {data_len}"
        )

    strings: list[str] = []

    for i in range(count):
        entry_pos = table_off + i * 4
        (str_data_off,) = struct.unpack_from("<I", data, entry_pos)

        if str_data_off >= data_len:
            raise DexParseError(
                f"string_data offset out of bounds: string[{i}] points to {str_data_off} (file size {data_len})"
            )

        # Read ULEB128 decoded character length
        _utf16_size, str_start = read_uleb128(data, str_data_off)

        # Locate terminating null byte
        null_idx = data.find(b"\x00", str_start)
        if null_idx == -1:
            raise DexParseError(
                f"Unterminated string data item at string[{i}] starting at offset {str_start}"
            )

        str_bytes_len = null_idx - str_start
        if str_bytes_len > MAX_STRING_LENGTH_BYTES:
            raise DexParseError(
                f"String at index {i} exceeds max string length ({str_bytes_len} > {MAX_STRING_LENGTH_BYTES})"
            )

        raw_bytes = data[str_start:null_idx]
        # Decode as UTF-8 (handling standard Modified UTF-8 gracefully)
        decoded = raw_bytes.decode("utf-8", errors="replace")
        strings.append(decoded)

    return strings


def extract_class_descriptors(
    data: bytes, header: DexHeader, strings: list[str]
) -> list[str]:
    """
    Extract class definition type descriptors from the DEX class_defs table.
    Traverses: class_defs[i].class_idx -> type_ids[class_idx] -> descriptor_idx -> strings[descriptor_idx].
    """
    data_len = len(data)

    # 1. Parse type_ids table to map type_id -> string_id
    type_count = header.type_ids_size
    type_off = header.type_ids_off
    type_bytes_needed = type_count * 4

    if type_off + type_bytes_needed > data_len:
        raise DexParseError(
            f"type_ids table out of bounds: offset {type_off} + {type_bytes_needed} bytes > file size {data_len}"
        )

    type_descriptors: list[int] = []
    for i in range(type_count):
        entry_pos = type_off + i * 4
        (descriptor_idx,) = struct.unpack_from("<I", data, entry_pos)
        if descriptor_idx >= len(strings):
            raise DexParseError(
                f"type_id[{i}] references invalid string index {descriptor_idx} (strings count {len(strings)})"
            )
        type_descriptors.append(descriptor_idx)

    # 2. Parse class_defs table
    class_count = header.class_defs_size
    class_off = header.class_defs_off
    # Each class_def_item is 8 uint32 fields = 32 bytes
    class_bytes_needed = class_count * 32

    if class_off + class_bytes_needed > data_len:
        raise DexParseError(
            f"class_defs table out of bounds: offset {class_off} + {class_bytes_needed} bytes > file size {data_len}"
        )

    class_descriptors: list[str] = []

    for i in range(class_count):
        item_pos = class_off + i * 32
        # class_idx is the first uint32 field
        (class_idx,) = struct.unpack_from("<I", data, item_pos)

        if class_idx >= len(type_descriptors):
            raise DexParseError(
                f"class_def[{i}] references invalid type_idx {class_idx} (type count {len(type_descriptors)})"
            )

        descriptor_str_idx = type_descriptors[class_idx]
        descriptor = strings[descriptor_str_idx]
        class_descriptors.append(descriptor)

    return class_descriptors


def inspect_dex_bytes(data: bytes, source_name: str = "classes.dex") -> DexFileInfo:
    """
    Parse and validate a complete DEX byte stream.
    Extracts header, string constants, and class definitions.
    """
    header = parse_dex_header(data)
    strings = extract_dex_strings(data, header)
    classes = extract_class_descriptors(data, header, strings)

    return DexFileInfo(
        name=source_name,
        header=header,
        classes_count=len(classes),
        strings_count=len(strings),
        class_descriptors=classes,
        strings=strings,
    )


def inspect_apk_dex(apk_path: Path) -> ApkDexSummary:
    """
    Inspect all DEX files within an APK archive.
    Discovers `classes.dex`, `classes2.dex`, ..., `classesN.dex` and aggregates
    unique class descriptors and string constants across all multidex files.
    """
    resolved_path = apk_path.resolve()
    if not resolved_path.is_file():
        raise FileNotFoundError(f"APK file not found: '{resolved_path}'")

    if not zipfile.is_zipfile(resolved_path):
        raise DexParseError(
            f"File '{resolved_path.name}' is not a valid ZIP/APK archive."
        )

    dex_file_infos: list[DexFileInfo] = []
    errors: list[str] = []

    with zipfile.ZipFile(resolved_path, "r") as zf:
        namelist = zf.namelist()
        # Find all DEX entries (classes.dex, classes2.dex, etc.)
        dex_names = sorted(
            [n for n in namelist if n.startswith("classes") and n.endswith(".dex")],
            key=lambda x: (len(x), x),  # Natural order: classes.dex, classes2.dex, ...
        )

        if not dex_names:
            raise DexParseError(
                f"APK archive '{resolved_path.name}' contains no DEX files."
            )

        for name in dex_names:
            try:
                dex_bytes = zf.read(name)
                info = inspect_dex_bytes(dex_bytes, source_name=name)
                dex_file_infos.append(info)
            except (DexError, zipfile.BadZipFile, OSError) as e:
                errors.append(f"Failed to inspect '{name}': {e}")

    # Aggregate classes and strings maintaining deterministic order
    seen_classes: set[str] = set()
    unique_classes: list[str] = []
    for info in dex_file_infos:
        for c in info.class_descriptors:
            if c not in seen_classes:
                seen_classes.add(c)
                unique_classes.append(c)

    seen_strings: set[str] = set()
    unique_strings: list[str] = []
    for info in dex_file_infos:
        for s in info.strings:
            if s not in seen_strings:
                seen_strings.add(s)
                unique_strings.append(s)

    total_classes = sum(info.classes_count for info in dex_file_infos)
    total_strings = sum(info.strings_count for info in dex_file_infos)

    return ApkDexSummary(
        dex_files_count=len(dex_file_infos),
        dex_names=[info.name for info in dex_file_infos],
        total_classes_count=total_classes,
        total_strings_count=total_strings,
        unique_class_descriptors=unique_classes,
        unique_strings=unique_strings,
        dex_files=dex_file_infos,
        errors=errors,
    )


def class_to_descriptor(class_name: str) -> str:
    """
    Convert a Java dot-separated class name to a DEX type descriptor.
    Example: 'com.example.Foo' -> 'Lcom/example/Foo;'
    """
    clean = class_name.strip()
    if clean.startswith("L") and clean.endswith(";"):
        return clean
    return "L" + clean.replace(".", "/") + ";"


def descriptor_to_class(descriptor: str) -> str:
    """
    Convert a DEX type descriptor to a Java dot-separated class name.
    Example: 'Lcom/example/Foo;' -> 'com.example.Foo'
    """
    clean = descriptor.strip()
    if clean.startswith("L") and clean.endswith(";"):
        clean = clean[1:-1]
    return clean.replace("/", ".")


def create_synthetic_dex(
    classes: list[str],
    strings: list[str] | None = None,
    version: str = "035\0",
) -> bytes:
    """
    Construct a valid, binary-compliant synthetic DEX file in memory.
    Used exclusively for isolated unit testing of DEX parsers and verification engines
    without requiring the Android SDK.
    """
    # 1. Collect all unique strings
    all_strings: list[str] = []
    seen: set[str] = set()

    for c in classes:
        desc = class_to_descriptor(c)
        if desc not in seen:
            seen.add(desc)
            all_strings.append(desc)

    if strings:
        for s in strings:
            if s not in seen:
                seen.add(s)
                all_strings.append(s)

    all_strings.sort()
    string_map = {s: i for i, s in enumerate(all_strings)}

    # 2. Type IDs correspond directly to class descriptors
    type_descriptors = [string_map[class_to_descriptor(c)] for c in classes]

    # 3. Build string data items
    string_data_bytes = bytearray()
    string_offsets: list[int] = []

    # Placeholder offset until header and tables are laid out
    for s in all_strings:
        encoded_str = s.encode("utf-8")
        item = encode_uleb128(len(s)) + encoded_str + b"\x00"
        string_offsets.append(len(string_data_bytes))
        string_data_bytes.extend(item)

    # 4. Layout sections:
    #   Header: 112 bytes
    #   string_ids: len(all_strings) * 4 bytes
    #   type_ids: len(type_descriptors) * 4 bytes
    #   class_defs: len(classes) * 32 bytes
    #   string_data: string_data_bytes
    header_size = DEX_HEADER_SIZE
    string_ids_off = header_size
    string_ids_size = len(all_strings)

    type_ids_off = string_ids_off + string_ids_size * 4
    type_ids_size = len(type_descriptors)

    class_defs_off = type_ids_off + type_ids_size * 4
    class_defs_size = len(classes)

    string_data_base_off = class_defs_off + class_defs_size * 32
    file_size = string_data_base_off + len(string_data_bytes)

    # 5. Pack tables
    string_ids_bin = bytearray()
    for off in string_offsets:
        string_ids_bin.extend(struct.pack("<I", string_data_base_off + off))

    type_ids_bin = bytearray()
    for desc_idx in type_descriptors:
        type_ids_bin.extend(struct.pack("<I", desc_idx))

    class_defs_bin = bytearray()
    for i in range(len(classes)):
        # class_idx is i
        item_bytes = struct.pack(
            "<IIIIIIII",
            i,  # class_idx
            0x0001,  # access_flags (ACC_PUBLIC)
            0xFFFFFFFF,  # superclass_idx (NO_INDEX)
            0,  # interfaces_off
            0xFFFFFFFF,  # source_file_idx
            0,  # annotations_off
            0,  # class_data_off
            0,  # static_values_off
        )
        class_defs_bin.extend(item_bytes)

    # 6. Build Header
    checksum = 0x12345678  # Dummy valid Adler32
    signature = b"\x00" * 20  # Dummy SHA-1
    endian_tag = ENDIAN_CONSTANT

    header_fmt = "<8sI20s" + "I" * 20
    header_bytes = struct.pack(
        header_fmt,
        DEX_MAGIC + version.encode("ascii")[:4],
        checksum,
        signature,
        file_size,
        header_size,
        endian_tag,
        0,
        0,  # link_size, link_off
        0,  # map_off
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        0,
        0,  # proto_ids
        0,
        0,  # field_ids
        0,
        0,  # method_ids
        class_defs_size,
        class_defs_off,
        len(string_data_bytes),  # data_size
        string_data_base_off,  # data_off
    )

    out = bytearray()
    out.extend(header_bytes)
    out.extend(string_ids_bin)
    out.extend(type_ids_bin)
    out.extend(class_defs_bin)
    out.extend(string_data_bytes)

    return bytes(out)
