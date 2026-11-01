"""
Unit tests for AppShield DEX Inspector and Parser (Plan 04-03).
Tests valid and malformed DEX headers, ULEB128 decoding, table bounds, string extraction,
class descriptor resolution, and multidex APK archives with synthetic fixtures.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from appshield.dex import (
    DEX_HEADER_SIZE,
    DEX_MAGIC,
    REVERSE_ENDIAN_CONSTANT,
    DexParseError,
    DexVersionError,
    class_to_descriptor,
    create_synthetic_dex,
    descriptor_to_class,
    encode_uleb128,
    extract_class_descriptors,
    extract_dex_strings,
    inspect_apk_dex,
    inspect_dex_bytes,
    parse_dex_header,
    read_uleb128,
)


class TestUleb128:
    def test_read_uleb128_single_byte(self) -> None:
        data = b"\x00\x01\x7f"
        val0, off0 = read_uleb128(data, 0)
        assert val0 == 0
        assert off0 == 1

        val1, off1 = read_uleb128(data, 1)
        assert val1 == 1
        assert off1 == 2

        val2, off2 = read_uleb128(data, 2)
        assert val2 == 127
        assert off2 == 3

    def test_read_uleb128_multi_byte(self) -> None:
        # 128 is encoded as 0x80, 0x01
        data = b"\x80\x01"
        val, off = read_uleb128(data, 0)
        assert val == 128
        assert off == 2

        # 624485 is encoded as 0xe5, 0x8e, 0x26
        data2 = b"\xe5\x8e\x26"
        val2, off2 = read_uleb128(data2, 0)
        assert val2 == 624485
        assert off2 == 3

    def test_read_uleb128_roundtrip_with_encode(self) -> None:
        test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 1_000_000]
        for v in test_values:
            encoded = encode_uleb128(v)
            decoded, next_off = read_uleb128(encoded, 0)
            assert decoded == v
            assert next_off == len(encoded)

    def test_read_uleb128_truncated(self) -> None:
        # Leading byte has high bit set (needs next byte), but buffer ends
        data = b"\x80"
        with pytest.raises(DexParseError, match="Unexpected end of file"):
            read_uleb128(data, 0)

    def test_read_uleb128_exceeds_5_bytes(self) -> None:
        # 6 bytes all with high bit set
        data = b"\x80\x80\x80\x80\x80\x80"
        with pytest.raises(DexParseError, match="exceeding 5 bytes"):
            read_uleb128(data, 0)


class TestDexHeaderParsing:
    def test_parse_valid_synthetic_dex(self) -> None:
        classes = ["com.example.Foo", "com.example.Bar"]
        strings = ["hello", "world"]
        data = create_synthetic_dex(classes=classes, strings=strings)

        header = parse_dex_header(data)
        assert header.magic.startswith(DEX_MAGIC)
        assert header.version == "035\0"
        assert header.is_little_endian is True
        assert header.header_size == DEX_HEADER_SIZE
        assert header.file_size == len(data)
        assert header.class_defs_size == len(classes)
        assert header.string_ids_size >= len(classes) + len(strings)

    def test_header_too_small(self) -> None:
        data = b"dex\n035\0"  # Only 8 bytes
        with pytest.raises(DexParseError, match="too small"):
            parse_dex_header(data)

    def test_invalid_magic_prefix(self) -> None:
        data = b"BAD\n035\0" + b"\x00" * 104
        with pytest.raises(DexVersionError, match="Invalid DEX magic prefix"):
            parse_dex_header(data)

    def test_unsupported_version(self) -> None:
        data = DEX_MAGIC + b"999\0" + b"\x00" * 104
        with pytest.raises(DexVersionError, match="Unsupported DEX version"):
            parse_dex_header(data)

    def test_dex_version_041_explicitly_rejected(self) -> None:
        data = DEX_MAGIC + b"041\0" + b"\x00" * 104
        with pytest.raises(DexVersionError, match="Container DEX format"):
            parse_dex_header(data)

    def test_invalid_endian_tag(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        # Mutate endian tag at offset 40
        bad_data = bytearray(raw)
        struct.pack_into("<I", bad_data, 40, 0x99999999)
        with pytest.raises(DexParseError, match="Invalid DEX endian tag"):
            parse_dex_header(bytes(bad_data))

    def test_big_endian_rejected(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        bad_data = bytearray(raw)
        struct.pack_into("<I", bad_data, 40, REVERSE_ENDIAN_CONSTANT)
        with pytest.raises(
            DexParseError, match="Big-endian DEX files are not supported"
        ):
            parse_dex_header(bytes(bad_data))

    def test_header_size_mismatch(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        bad_data = bytearray(raw)
        struct.pack_into("<I", bad_data, 36, 120)  # offset 36 is header_size
        with pytest.raises(DexParseError, match="Invalid DEX header size"):
            parse_dex_header(bytes(bad_data))

    def test_truncated_file_size_check(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        # Slice off last 10 bytes so actual len < declared file_size
        truncated = raw[:-10]
        with pytest.raises(DexParseError, match="Truncated DEX file"):
            parse_dex_header(truncated)


class TestDexExtractionBounds:
    def test_string_ids_out_of_bounds(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        bad_data = bytearray(raw)
        # offset 60 is string_ids_off; set to huge offset
        struct.pack_into("<I", bad_data, 60, len(raw) + 1000)
        header = parse_dex_header(bytes(bad_data))
        with pytest.raises(DexParseError, match="string_ids table out of bounds"):
            extract_dex_strings(bytes(bad_data), header)

    def test_string_data_offset_out_of_bounds(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        bad_data = bytearray(raw)
        header = parse_dex_header(raw)
        # String 0 offset is at header.string_ids_off
        struct.pack_into("<I", bad_data, header.string_ids_off, len(raw) + 500)
        with pytest.raises(DexParseError, match="string_data offset out of bounds"):
            extract_dex_strings(bytes(bad_data), header)

    def test_unterminated_string_data(self) -> None:
        classes = ["com.example.Foo"]
        raw = create_synthetic_dex(classes=classes)
        bad_data = bytearray(raw)
        header = parse_dex_header(raw)
        # Overwrite trailing null bytes in data section with 'A'
        for i in range(header.data_off, len(bad_data)):
            if bad_data[i] == 0:
                bad_data[i] = ord("A")
        with pytest.raises(DexParseError, match="Unterminated string data item"):
            extract_dex_strings(bytes(bad_data), header)

    def test_type_ids_out_of_bounds(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        bad_data = bytearray(raw)
        # offset 68 is type_ids_off
        struct.pack_into("<I", bad_data, 68, len(raw) + 1000)
        header = parse_dex_header(bytes(bad_data))
        strings = extract_dex_strings(raw, header)
        with pytest.raises(DexParseError, match="type_ids table out of bounds"):
            extract_class_descriptors(bytes(bad_data), header, strings)

    def test_class_defs_out_of_bounds(self) -> None:
        raw = create_synthetic_dex(["com.example.Foo"])
        bad_data = bytearray(raw)
        # offset 100 is class_defs_off
        struct.pack_into("<I", bad_data, 100, len(raw) + 1000)
        header = parse_dex_header(bytes(bad_data))
        strings = extract_dex_strings(raw, header)
        with pytest.raises(DexParseError, match="class_defs table out of bounds"):
            extract_class_descriptors(bytes(bad_data), header, strings)


class TestDexInspectionAndMultidex:
    def test_inspect_dex_bytes_complete(self) -> None:
        classes = ["com.example.ServiceA", "com.example.ServiceB"]
        strings = ["secret_token_123", "MainActivity"]
        data = create_synthetic_dex(classes=classes, strings=strings)

        info = inspect_dex_bytes(data, source_name="test.dex")
        assert info.name == "test.dex"
        assert info.classes_count == 2
        assert "Lcom/example/ServiceA;" in info.class_descriptors
        assert "Lcom/example/ServiceB;" in info.class_descriptors
        assert "secret_token_123" in info.strings
        assert "MainActivity" in info.strings

    def test_inspect_apk_dex_single_and_multidex(self, tmp_path: Path) -> None:
        apk_path = tmp_path / "multidex_sample.apk"

        dex1_classes = ["com.example.Main", "com.example.Foo"]
        dex1_strings = ["token_in_dex1"]
        dex1 = create_synthetic_dex(classes=dex1_classes, strings=dex1_strings)

        dex2_classes = ["com.example.Bar", "com.example.Baz"]
        dex2_strings = ["token_in_dex2"]
        dex2 = create_synthetic_dex(classes=dex2_classes, strings=dex2_strings)

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<dummy-manifest/>")
            zf.writestr("classes.dex", dex1)
            zf.writestr("classes2.dex", dex2)

        summary = inspect_apk_dex(apk_path)
        assert summary.dex_files_count == 2
        assert summary.dex_names == ["classes.dex", "classes2.dex"]
        assert summary.total_classes_count == 4
        assert "Lcom/example/Main;" in summary.unique_class_descriptors
        assert "Lcom/example/Bar;" in summary.unique_class_descriptors
        assert "token_in_dex1" in summary.unique_strings
        assert "token_in_dex2" in summary.unique_strings
        assert len(summary.errors) == 0

    def test_inspect_apk_dex_no_dex_files_raises(self, tmp_path: Path) -> None:
        apk_path = tmp_path / "empty_archive.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<dummy-manifest/>")

        with pytest.raises(DexParseError, match="contains no DEX files"):
            inspect_apk_dex(apk_path)

    def test_inspect_apk_dex_missing_file_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "non_existent.apk"
        with pytest.raises(FileNotFoundError):
            inspect_apk_dex(missing)

    def test_inspect_apk_dex_invalid_zip_raises(self, tmp_path: Path) -> None:
        corrupted = tmp_path / "corrupted.apk"
        corrupted.write_bytes(b"not a zip file")
        with pytest.raises(DexParseError, match="not a valid ZIP/APK archive"):
            inspect_apk_dex(corrupted)


class TestClassDescriptorConversions:
    def test_class_to_descriptor(self) -> None:
        assert class_to_descriptor("com.example.Foo") == "Lcom/example/Foo;"
        assert class_to_descriptor("MainActivity") == "LMainActivity;"
        assert class_to_descriptor("a.b.c") == "La/b/c;"
        # Idempotent if already a descriptor
        assert class_to_descriptor("Lcom/example/Foo;") == "Lcom/example/Foo;"

    def test_descriptor_to_class(self) -> None:
        assert descriptor_to_class("Lcom/example/Foo;") == "com.example.Foo"
        assert descriptor_to_class("LMainActivity;") == "MainActivity"
        assert descriptor_to_class("La/b/c;") == "a.b.c"
        # Handles non-descriptor strings gracefully
        assert descriptor_to_class("com.example.Bar") == "com.example.Bar"
