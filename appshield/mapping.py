"""
AppShield R8 Mapping Parser.
Parses ProGuard / R8 mapping.txt files into structured class, method, and field mappings.
Computes aggregate renaming statistics and compiler metadata without exposing raw identifiers
or sensitive paths in public reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Regular expressions for R8 / ProGuard mapping grammar
CLASS_LINE_REGEX = re.compile(r"^([a-zA-Z0-9_$.]+)\s*->\s*([a-zA-Z0-9_$.]+):$")
METHOD_LINE_REGEX = re.compile(
    r"^\s+(?:(\d+):(\d+):)?([a-zA-Z0-9_$.\[\]]+)\s+([a-zA-Z0-9_$<>]+)\(([^)]*)\)\s*->\s*([a-zA-Z0-9_$<>]+)$"
)
FIELD_LINE_REGEX = re.compile(
    r"^\s+([a-zA-Z0-9_$.\[\]]+)\s+([a-zA-Z0-9_$]+)\s*->\s*([a-zA-Z0-9_$]+)$"
)
COMMENT_META_REGEX = re.compile(r"^#\s*([a-zA-Z0-9_-]+)\s*:\s*(.+)$")


class MappingParseError(Exception):
    """Raised when an R8 mapping file cannot be parsed or contains invalid syntax."""


@dataclass(frozen=True)
class MethodMapping:
    """Mapping for an individual class method."""

    original_name: str
    obfuscated_name: str
    return_type: str
    parameters: str
    line_start: int | None = None
    line_end: int | None = None

    @property
    def is_renamed(self) -> bool:
        # Constructors and static initializers are not considered renamed
        if self.original_name in ("<init>", "<clinit>"):
            return False
        return self.original_name != self.obfuscated_name


@dataclass(frozen=True)
class FieldMapping:
    """Mapping for an individual class field."""

    original_name: str
    obfuscated_name: str
    field_type: str

    @property
    def is_renamed(self) -> bool:
        return self.original_name != self.obfuscated_name


@dataclass(frozen=True)
class ClassMapping:
    """Mapping for a class and its member methods and fields."""

    original_name: str
    obfuscated_name: str
    methods: list[MethodMapping] = field(default_factory=list)
    fields: list[FieldMapping] = field(default_factory=list)

    @property
    def is_renamed(self) -> bool:
        return self.original_name != self.obfuscated_name

    @property
    def renamed_methods_count(self) -> int:
        return sum(1 for m in self.methods if m.is_renamed)

    @property
    def renamed_fields_count(self) -> int:
        return sum(1 for f in self.fields if f.is_renamed)


@dataclass(frozen=True)
class R8MappingSummary:
    """Aggregate statistics and parsed structures from an R8 mapping file."""

    total_classes: int
    renamed_classes_count: int
    kept_classes_count: int
    class_renaming_ratio: float
    total_methods: int
    renamed_methods_count: int
    method_renaming_ratio: float
    compiler_metadata: dict[str, str]
    classes: dict[str, ClassMapping] = field(default_factory=dict)
    obfuscated_to_original: dict[str, str] = field(default_factory=dict)


def parse_r8_mapping(content_or_path: str | Path) -> R8MappingSummary:
    """
    Parse an R8 or ProGuard mapping file into structured mappings and compute
    aggregate statistics.
    Accepts a Path to mapping.txt or the raw file text string.
    """
    if isinstance(content_or_path, Path):
        resolved_path = content_or_path.resolve()
        if not resolved_path.exists():
            raise FileNotFoundError(f"Mapping file not found: '{resolved_path}'")
        if not resolved_path.is_file():
            raise MappingParseError(
                f"Mapping path is not a regular file: '{resolved_path}'"
            )
        raw_bytes = resolved_path.read_bytes()
        if b"\x00" in raw_bytes:
            raise MappingParseError(
                f"Mapping file '{resolved_path.name}' contains binary NUL bytes and cannot be parsed as R8 mapping text."
            )
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise MappingParseError(
                f"Mapping file '{resolved_path.name}' is not valid UTF-8 text: {e}"
            ) from e
    else:
        text = content_or_path
        if "\x00" in text:
            raise MappingParseError(
                "Mapping text contains binary NUL bytes and cannot be parsed as R8 mapping text."
            )

    lines = text.splitlines()
    classes: dict[str, ClassMapping] = {}
    obf_to_orig: dict[str, str] = {}
    compiler_meta: dict[str, str] = {}

    current_class_orig: str | None = None
    current_class_obf: str | None = None
    current_methods: list[MethodMapping] = []
    current_fields: list[FieldMapping] = []

    def commit_current_class() -> None:
        if current_class_orig is not None and current_class_obf is not None:
            mapping = ClassMapping(
                original_name=current_class_orig,
                obfuscated_name=current_class_obf,
                methods=list(current_methods),
                fields=list(current_fields),
            )
            classes[current_class_orig] = mapping
            obf_to_orig[current_class_obf] = current_class_orig

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # Header or inline R8 metadata comments (e.g. "# compiler: R8", "# {\"id\":...}")
        if stripped.startswith("#"):
            meta_match = COMMENT_META_REGEX.match(stripped)
            if meta_match:
                key, val = meta_match.group(1).lower(), meta_match.group(2).strip()
                compiler_meta[key] = val
            continue

        # Class definition line: "com.example.Foo -> a.b.c:"
        class_match = CLASS_LINE_REGEX.match(stripped)
        if class_match and not line[:1].isspace():
            commit_current_class()
            current_class_orig = class_match.group(1)
            current_class_obf = class_match.group(2)
            current_methods = []
            current_fields = []
            continue

        # Unindented or pre-class non-comment lines that are not valid class mappings are malformed
        if current_class_orig is None or not line[:1].isspace():
            raise MappingParseError(
                f"Malformed R8 mapping class entry at line {line_no}: '{stripped[:80]}'"
            )

        # Method line: "1:3:void foo(int) -> a" or "void foo() -> a"
        method_match = METHOD_LINE_REGEX.match(line)
        if method_match:
            line_start_str, line_end_str, ret_type, orig_method, params, obf_method = (
                method_match.groups()
            )
            l_start = int(line_start_str) if line_start_str else None
            l_end = int(line_end_str) if line_end_str else None

            current_methods.append(
                MethodMapping(
                    original_name=orig_method,
                    obfuscated_name=obf_method,
                    return_type=ret_type,
                    parameters=params,
                    line_start=l_start,
                    line_end=l_end,
                )
            )
            continue

        # Field line: "int count -> a"
        field_match = FIELD_LINE_REGEX.match(line)
        if field_match:
            f_type, orig_field, obf_field = field_match.groups()
            current_fields.append(
                FieldMapping(
                    original_name=orig_field,
                    obfuscated_name=obf_field,
                    field_type=f_type,
                )
            )
            continue

        # Validate extended R8 member syntax (e.g. outlined/inlined frames) has valid 'lhs -> rhs'
        if " -> " not in stripped:
            raise MappingParseError(
                f"Malformed R8 mapping member entry at line {line_no}: '{stripped[:80]}'"
            )
        lhs_part, rhs_part = stripped.split(" -> ", 1)
        if (
            not lhs_part.strip()
            or not rhs_part.strip()
            or rhs_part.strip().endswith(":")
        ):
            raise MappingParseError(
                f"Malformed R8 mapping member entry at line {line_no}: '{stripped[:80]}'"
            )

    # Commit the last class
    commit_current_class()

    total_classes = len(classes)
    renamed_classes = sum(1 for c in classes.values() if c.is_renamed)
    kept_classes = total_classes - renamed_classes
    class_ratio = (renamed_classes / total_classes) if total_classes > 0 else 0.0

    total_methods = sum(len(c.methods) for c in classes.values())
    renamed_methods = sum(c.renamed_methods_count for c in classes.values())
    method_ratio = (renamed_methods / total_methods) if total_methods > 0 else 0.0

    return R8MappingSummary(
        total_classes=total_classes,
        renamed_classes_count=renamed_classes,
        kept_classes_count=kept_classes,
        class_renaming_ratio=class_ratio,
        total_methods=total_methods,
        renamed_methods_count=renamed_methods,
        method_renaming_ratio=method_ratio,
        compiler_metadata=compiler_meta,
        classes=classes,
        obfuscated_to_original=obf_to_orig,
    )
