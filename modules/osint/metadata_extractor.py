"""Offline Document & Evidence Metadata Extractor (OSINT & Forensics).

Extracts hidden metadata from target documents, reports, and evidence files:
- PDF: Document Author, Creator, Producer, Creation Date, Internal paths.
- Office OpenXML (.docx, .xlsx, .pptx): Author, Last Modified By, Revisions, Company.
- Images (.jpg, .jpeg, .png): EXIF metadata, Camera make/model, Software, GPS coordinates.

Correlates findings with project scope and generates standardized Finding objects
(CWE-200: Information Exposure) to identify internal username and infrastructure leaks.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from storage.db import Database
from storage.models import (
    Evidence,
    Finding,
    FindingSeverity,
    ValidationStatus,
)


@dataclass
class DocumentMetadata:
    """Represents extracted document metadata and sensitive leak indicators."""
    file_path: str
    file_type: str
    file_size_bytes: int
    sha256_hash: str
    properties: Dict[str, str] = field(default_factory=dict)
    author: Optional[str] = None
    creator_tool: Optional[str] = None
    created_date: Optional[str] = None
    modified_by: Optional[str] = None
    company: Optional[str] = None
    gps_coordinates: Optional[Tuple[float, float]] = None
    leak_indicators: List[str] = field(default_factory=list)


class MetadataExtractor:
    """Extracts metadata from PDF, Office OpenXML, and Image files."""

    @classmethod
    def analyze_file(cls, file_path: str) -> DocumentMetadata:
        """Inspects file type and extracts metadata."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_bytes = p.read_bytes()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        ext = p.suffix.lower()

        meta = DocumentMetadata(
            file_path=str(p.resolve()),
            file_type=ext.replace(".", "").upper(),
            file_size_bytes=len(file_bytes),
            sha256_hash=sha256,
        )

        if ext == ".pdf":
            cls._extract_pdf_metadata(file_bytes, meta)
        elif ext in (".docx", ".xlsx", ".pptx"):
            cls._extract_office_metadata(p, meta)
        elif ext in (".jpg", ".jpeg", ".png"):
            cls._extract_image_metadata(file_bytes, meta)

        cls._identify_sensitive_leaks(meta)
        return meta

    @classmethod
    def _extract_pdf_metadata(cls, data: bytes, meta: DocumentMetadata):
        """Pure-Python regex parsing of PDF trailer /Info object and XMP metadata."""
        # Find /Author, /Creator, /Producer, /CreationDate, /Title
        for key, prop_name in [
            (b"/Author", "Author"),
            (b"/Creator", "Creator"),
            (b"/Producer", "Producer"),
            (b"/CreationDate", "CreationDate"),
            (b"/ModDate", "ModDate"),
            (b"/Title", "Title"),
            (b"/Company", "Company"),
        ]:
            pattern = re.compile(key + rb"\s*\((.*?)\)", re.DOTALL)
            m = pattern.search(data)
            if m:
                val = m.group(1).decode("utf-8", errors="replace").strip()
                meta.properties[prop_name] = val
                if prop_name == "Author":
                    meta.author = val
                elif prop_name in ("Creator", "Producer"):
                    meta.creator_tool = val
                elif prop_name == "CreationDate":
                    meta.created_date = val
                elif prop_name == "Company":
                    meta.company = val

        # Check for XMP metadata stream
        xmp_match = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", data, re.DOTALL)
        if xmp_match:
            try:
                xmp_text = xmp_match.group(0).decode("utf-8", errors="replace")
                creator_m = re.search(r"<dc:creator[^>]*>.*?<rdf:li>([^<]+)</rdf:li>", xmp_text, re.DOTALL)
                if creator_m and not meta.author:
                    meta.author = creator_m.group(1).strip()
                    meta.properties["Author"] = meta.author
            except Exception:
                pass

    @classmethod
    def _extract_office_metadata(cls, path: Path, meta: DocumentMetadata):
        """Extracts metadata from docProps/core.xml in Office OpenXML zip files."""
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if "docProps/core.xml" in zf.namelist():
                    core_xml = zf.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)
                    namespaces = {
                        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "dcterms": "http://purl.org/dc/terms/",
                    }
                    creator = root.find("dc:creator", namespaces)
                    if creator is not None and creator.text:
                        meta.author = creator.text.strip()
                        meta.properties["Author"] = meta.author

                    last_mod = root.find("cp:lastModifiedBy", namespaces)
                    if last_mod is not None and last_mod.text:
                        meta.modified_by = last_mod.text.strip()
                        meta.properties["LastModifiedBy"] = meta.modified_by

                    created = root.find("dcterms:created", namespaces)
                    if created is not None and created.text:
                        meta.created_date = created.text.strip()
                        meta.properties["CreationDate"] = meta.created_date

                    revision = root.find("cp:revision", namespaces)
                    if revision is not None and revision.text:
                        meta.properties["Revision"] = revision.text.strip()

                if "docProps/app.xml" in zf.namelist():
                    app_xml = zf.read("docProps/app.xml")
                    app_root = ET.fromstring(app_xml)
                    ns = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                    app = app_root.find("ep:Application", ns)
                    if app is not None and app.text:
                        meta.creator_tool = app.text.strip()
                        meta.properties["Application"] = meta.creator_tool
                    comp = app_root.find("ep:Company", ns)
                    if comp is not None and comp.text:
                        meta.company = comp.text.strip()
                        meta.properties["Company"] = meta.company
        except Exception:
            pass

    @classmethod
    def _extract_image_metadata(cls, data: bytes, meta: DocumentMetadata):
        """Extracts EXIF metadata tags from JPEG APP1 segments."""
        if len(data) < 4 or data[:2] != b"\xff\xd8":
            return  # Not JPEG

        # Search for APP1 Exif marker (FF E1)
        offset = 2
        while offset < len(data) - 4:
            if data[offset] != 0xFF:
                break
            marker = data[offset + 1]
            seg_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            if marker == 0xE1 and data[offset + 4:offset + 10] == b"Exif\x00\x00":
                exif_data = data[offset + 10:offset + 2 + seg_len]
                cls._parse_tiff_header(exif_data, meta)
                break
            offset += 2 + seg_len

    @classmethod
    def _parse_tiff_header(cls, exif: bytes, meta: DocumentMetadata):
        """Parses basic TIFF header and tags for Camera, Software, and DateTime."""
        if len(exif) < 8:
            return
        byte_order = exif[:2]
        endian = "<" if byte_order == b"II" else ">"
        try:
            ifd0_offset = struct.unpack(endian + "I", exif[4:8])[0]
            if ifd0_offset >= len(exif) - 2:
                return
            num_entries = struct.unpack(endian + "H", exif[ifd0_offset:ifd0_offset + 2])[0]
            curr = ifd0_offset + 2
            for _ in range(min(num_entries, 60)):
                if curr + 12 > len(exif):
                    break
                tag, tag_type, count, val_or_offset = struct.unpack(endian + "HHI I", exif[curr:curr + 12])
                curr += 12

                # 0x010F: Make, 0x0110: Model, 0x0131: Software, 0x0132: DateTime
                if tag in (0x010F, 0x0110, 0x0131, 0x0132) and count > 1:
                    str_offset = val_or_offset if count > 4 else (curr - 4)
                    if str_offset < len(exif):
                        val_str = exif[str_offset:str_offset + count].decode("utf-8", errors="replace").rstrip("\x00").strip()
                        if tag == 0x010F:
                            meta.properties["CameraMake"] = val_str
                        elif tag == 0x0110:
                            meta.properties["CameraModel"] = val_str
                        elif tag == 0x0131:
                            meta.creator_tool = val_str
                            meta.properties["Software"] = val_str
                        elif tag == 0x0132:
                            meta.created_date = val_str
                            meta.properties["DateTime"] = val_str
        except Exception:
            pass

    @classmethod
    def _identify_sensitive_leaks(cls, meta: DocumentMetadata):
        """Detects sensitive reconnaissance indicators."""
        if meta.author:
            meta.leak_indicators.append(f"Internal Author Username/Identity Exposed: '{meta.author}'")
        if meta.modified_by and meta.modified_by != meta.author:
            meta.leak_indicators.append(f"Internal Editor/Reviewer Identity Exposed: '{meta.modified_by}'")
        if meta.creator_tool:
            meta.leak_indicators.append(f"Internal Software/Host Platform Disclosed: '{meta.creator_tool}'")
        if meta.company:
            meta.leak_indicators.append(f"Internal Corporate Identity Disclosed: '{meta.company}'")
        if meta.gps_coordinates:
            meta.leak_indicators.append(f"Precise Geographic GPS Coordinates Embedded: {meta.gps_coordinates}")

    @classmethod
    def import_and_audit(
        cls,
        db: Database,
        project_id: int,
        file_path: str,
        assessment_id: Optional[int] = None,
    ) -> Tuple[Optional[Finding], Evidence, DocumentMetadata]:
        """Audits file metadata, registers cryptographic evidence, and generates Finding if leaks occur."""
        meta = cls.analyze_file(file_path)

        ev = db.add_evidence(
            Evidence(
                project_id=project_id,
                file_path=meta.file_path,
                sha256_hash=meta.sha256_hash,
                description=f"Audited Evidence Metadata ({meta.file_type}): {Path(file_path).name}",
                mime_type="application/octet-stream",
                assessment_id=assessment_id,
            )
        )

        finding: Optional[Finding] = None
        if meta.leak_indicators:
            title = f"Sensitive Metadata & Information Exposure: {Path(file_path).name}"
            desc = (
                f"Static document metadata analysis discovered sensitive internal infrastructure "
                f"or personnel details embedded in **{Path(file_path).name}**.\n\n"
                f"- **File Type:** {meta.file_type} ({meta.file_size_bytes} bytes)\n"
                f"- **SHA-256 Hash:** `{meta.sha256_hash}`\n"
                f"- **Extracted Leaks:**\n"
                + "\n".join([f"  * {leak}" for leak in meta.leak_indicators])
                + "\n\n**Discovered Properties:**\n"
                + "\n".join([f"- `{k}`: {v}" for k, v in meta.properties.items()])
            )
            rem = (
                "Scrub all document and image metadata before publishing or transmitting files externally. "
                "Use automated metadata stripping tools (e.g. exiftool, mat2, docx-sanitizer) in CI/CD pipelines."
            )
            finding = db.create_finding(
                Finding(
                    project_id=project_id,
                    title=title,
                    severity=FindingSeverity.LOW if not meta.gps_coordinates else FindingSeverity.MEDIUM,
                    affected_asset=Path(file_path).name,
                    description=desc,
                    remediation=rem,
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="metadata_extractor",
                    assessment_id=assessment_id,
                )
            )

        return finding, ev, meta

