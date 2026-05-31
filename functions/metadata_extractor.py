# functions/metadata_extractor.py
# EXIF and document metadata extraction from publicly accessible files
# Educational Purpose Only - IntelCore-OSINT Framework

import re
import io
import time
import struct
import socket
import requests
import urllib.parse
from typing import Dict, Any, List, Optional
from logger import get_logger

logger = get_logger()

TIMEOUT = 15
MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024  # 10 MB cap per file
USER_AGENT = 'Mozilla/5.0 (compatible; IntelCore-OSINT/1.0)'

# ─────────────────────────────────────────────
# File type patterns to search for
# ─────────────────────────────────────────────

FILE_PATTERNS = {
    'pdf':  r'\.pdf(\?[^"\s]*)?',
    'docx': r'\.docx?(\?[^"\s]*)?',
    'xlsx': r'\.xlsx?(\?[^"\s]*)?',
    'pptx': r'\.pptx?(\?[^"\s]*)?',
    'jpg':  r'\.jpe?g(\?[^"\s]*)?',
    'png':  r'\.png(\?[^"\s]*)?',
}

# ─────────────────────────────────────────────
# EXIF extraction (pure-Python, no Pillow dependency)
# ─────────────────────────────────────────────

EXIF_TAGS = {
    0x010F: 'Make',
    0x0110: 'Model',
    0x0112: 'Orientation',
    0x011A: 'XResolution',
    0x011B: 'YResolution',
    0x0128: 'ResolutionUnit',
    0x0131: 'Software',
    0x0132: 'DateTime',
    0x013B: 'Artist',
    0x8769: 'ExifIFD',
    0x8825: 'GPSIFD',
    0x8298: 'Copyright',
    0x9003: 'DateTimeOriginal',
    0x9004: 'DateTimeDigitized',
    0x9291: 'SubSecTimeOriginal',
    0xA430: 'CameraOwnerName',
    0xA431: 'BodySerialNumber',
    0x0002: 'GPSLatitude',
    0x0004: 'GPSLongitude',
    0x0001: 'GPSLatitudeRef',
    0x0003: 'GPSLongitudeRef',
    0x001D: 'GPSDateStamp',
}

def _read_ifd(data: bytes, offset: int, endian: str) -> Dict[str, Any]:
    """Read an IFD block from EXIF data."""
    tags = {}
    try:
        num_entries = struct.unpack_from(f'{endian}H', data, offset)[0]
        offset += 2
        for _ in range(num_entries):
            if offset + 12 > len(data):
                break
            tag_id, type_id, count = struct.unpack_from(f'{endian}HHI', data, offset)
            value_raw = data[offset + 8: offset + 12]

            if tag_id in EXIF_TAGS:
                try:
                    if type_id == 2:  # ASCII
                        if count <= 4:
                            value = value_raw[:count].decode('ascii', errors='ignore').rstrip('\x00')
                        else:
                            val_offset = struct.unpack_from(f'{endian}I', data, offset + 8)[0]
                            value = data[val_offset: val_offset + count].decode('ascii', errors='ignore').rstrip('\x00')
                    elif type_id in (3, 4):  # SHORT or LONG
                        fmt = f'{endian}{"H" if type_id == 3 else "I"}'
                        value = struct.unpack_from(fmt, value_raw)[0]
                    elif type_id == 5:  # RATIONAL
                        val_offset = struct.unpack_from(f'{endian}I', data, offset + 8)[0]
                        num, denom = struct.unpack_from(f'{endian}II', data, val_offset)
                        value = round(num / denom, 6) if denom != 0 else None
                    else:
                        value = None
                    if value is not None:
                        tags[EXIF_TAGS[tag_id]] = value
                except Exception:
                    pass
            offset += 12
    except Exception:
        pass
    return tags


def _extract_jpeg_exif(data: bytes) -> Dict[str, Any]:
    """Extract EXIF data from a JPEG file."""
    exif = {}
    if len(data) < 4 or data[:2] != b'\xff\xd8':
        return exif

    pos = 2
    while pos < len(data) - 2:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xE1:  # APP1 - EXIF
            length = struct.unpack_from('>H', data, pos + 2)[0]
            app1_data = data[pos + 4: pos + 2 + length]
            if app1_data[:6] == b'Exif\x00\x00':
                tiff_data = app1_data[6:]
                endian = '>' if tiff_data[:2] == b'MM' else '<'
                ifd_offset = struct.unpack_from(f'{endian}I', tiff_data, 4)[0]
                exif = _read_ifd(tiff_data, ifd_offset, endian)
                # Check GPS sub-IFD
                if 'GPSIFD' in exif:
                    gps_offset = exif.pop('GPSIFD')
                    try:
                        gps_tags = _read_ifd(tiff_data, gps_offset, endian)
                        if gps_tags:
                            exif['GPS'] = gps_tags
                    except Exception:
                        pass
            break
        elif marker in (0xD9, 0xDA):  # End of image / Start of scan
            break
        else:
            try:
                length = struct.unpack_from('>H', data, pos + 2)[0]
                pos += 2 + length
            except Exception:
                break
    return exif


# ─────────────────────────────────────────────
# PDF Metadata extraction (pure-Python)
# ─────────────────────────────────────────────

def _extract_pdf_metadata(data: bytes) -> Dict[str, Any]:
    """Extract metadata from a PDF file using raw byte parsing."""
    meta = {}
    try:
        text = data[:65536].decode('latin-1', errors='ignore')

        # Look for /Info dictionary
        info_match = re.search(r'/Info\s+\d+\s+\d+\s+R', text)
        if not info_match:
            # Try inline info block
            info_block_match = re.search(
                r'<<\s*((?:/(?:Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate)[^>]*)+)>>',
                text, re.DOTALL
            )
            if info_block_match:
                block = info_block_match.group(1)
            else:
                block = text
        else:
            block = text

        # Extract common PDF metadata fields
        for field in ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer',
                      'CreationDate', 'ModDate']:
            match = re.search(rf'/{field}\s*\(([^)]*)\)', block)
            if match:
                meta[field] = match.group(1).strip()

        # XMP metadata
        xmp_match = re.search(r'<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>', text, re.DOTALL)
        if xmp_match:
            xmp = xmp_match.group(1)
            for tag in ['dc:title', 'dc:creator', 'dc:description', 'xmp:CreateDate',
                        'xmp:ModifyDate', 'pdf:Producer', 'xmp:CreatorTool']:
                m = re.search(rf'<{tag}[^>]*>([^<]+)</{tag}>', xmp)
                if m:
                    meta[f'XMP_{tag}'] = m.group(1).strip()

    except Exception as e:
        meta['error'] = str(e)
    return meta


# ─────────────────────────────────────────────
# DOCX/XLSX/PPTX Metadata extraction (ZIP-based)
# ─────────────────────────────────────────────

def _extract_office_metadata(data: bytes, filename: str) -> Dict[str, Any]:
    """Extract metadata from Office Open XML files (docx, xlsx, pptx)."""
    meta = {}
    try:
        import zipfile
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, 'r') as z:
            # Core properties
            core_paths = ['docProps/core.xml', 'docProps/app.xml']
            for path in core_paths:
                if path in z.namelist():
                    xml = z.read(path).decode('utf-8', errors='ignore')
                    for field in ['title', 'creator', 'lastModifiedBy', 'created', 'modified',
                                  'subject', 'keywords', 'description', 'Application',
                                  'Company', 'Manager']:
                        m = re.search(rf'<[a-z:]*{field}[^>]*>([^<]+)</', xml, re.IGNORECASE)
                        if m:
                            meta[field] = m.group(1).strip()
    except Exception as e:
        meta['error'] = str(e)
    return meta


# ─────────────────────────────────────────────
# Web crawler – find publicly accessible files
# ─────────────────────────────────────────────

def _discover_files(domain: str, max_files: int = 15) -> List[Dict[str, str]]:
    """Discover publicly accessible documents and images on the domain."""
    discovered = []
    visited = set()
    to_visit = [f"https://{domain}", f"http://{domain}"]

    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    while to_visit and len(discovered) < max_files:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True,
                               stream=True)
            # Read max 500KB of HTML
            content = b''
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 512 * 1024:
                    break

            html = content.decode('utf-8', errors='ignore')

            # Find file links
            for file_type, pattern in FILE_PATTERNS.items():
                links = re.findall(
                    rf'(?:href|src)=["\']([^"\']*{pattern})',
                    html, re.IGNORECASE
                )
                for link in links:
                    absolute_url = urllib.parse.urljoin(url, link)
                    if absolute_url not in [d['url'] for d in discovered]:
                        discovered.append({'url': absolute_url, 'type': file_type})
                    if len(discovered) >= max_files:
                        break

        except Exception:
            continue

    return discovered


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def metadata_extractor(domain: str) -> Dict[str, Any]:
    """
    Discover and extract metadata from publicly accessible files on the target domain.
    
    Supports:
    - JPEG/PNG images: EXIF data (camera make/model, GPS coordinates, timestamps, software)
    - PDF documents: Author, Creator, Producer, CreationDate, XMP metadata
    - Office Open XML (docx, xlsx, pptx): Title, Creator, Company, LastModifiedBy, dates
    
    Args:
        domain: Target domain (e.g. 'example.com')
        
    Returns:
        Dictionary with all discovered files and their extracted metadata
    """
    logger.info(f"[METADATA] Starting metadata extraction for: {domain}")
    start_time = time.time()

    results = {
        'domain': domain,
        'module': 'metadata_extractor',
        'status': 'completed',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'files_discovered': 0,
        'files_with_metadata': 0,
        'sensitive_findings': [],
        'extracted_metadata': [],
        'summary': {
            'unique_authors': [],
            'unique_software': [],
            'gps_coordinates_found': 0,
            'emails_found': [],
            'organizations_found': [],
        }
    }

    # Step 1: Discover files
    logger.info(f"[METADATA] Discovering files on {domain}...")
    discovered = _discover_files(domain, max_files=15)
    results['files_discovered'] = len(discovered)
    logger.info(f"[METADATA] Found {len(discovered)} files to analyze")

    # Step 2: Download and extract metadata from each file
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    authors = set()
    software_set = set()
    emails_set = set()
    orgs_set = set()
    gps_count = 0

    for file_info in discovered:
        file_url = file_info['url']
        file_type = file_info['type']
        entry = {
            'url': file_url,
            'type': file_type,
            'filename': file_url.split('/')[-1].split('?')[0],
            'metadata': {},
            'sensitive': False,
            'sensitive_items': []
        }

        try:
            resp = session.get(file_url, timeout=TIMEOUT, stream=True)
            if resp.status_code != 200:
                continue

            # Download with size cap
            data = b''
            for chunk in resp.iter_content(chunk_size=16384):
                data += chunk
                if len(data) > MAX_DOWNLOAD_SIZE:
                    break

            if not data:
                continue

            # Extract metadata based on type
            meta = {}
            if file_type in ('jpg', 'jpeg'):
                meta = _extract_jpeg_exif(data)
            elif file_type == 'pdf':
                meta = _extract_pdf_metadata(data)
            elif file_type in ('docx', 'xlsx', 'pptx'):
                meta = _extract_office_metadata(data, entry['filename'])

            if meta:
                entry['metadata'] = meta
                results['files_with_metadata'] += 1

                # Collect interesting fields
                for key in ('Author', 'creator', 'Artist', 'Make', 'Model', 'Software',
                            'Producer', 'Creator', 'Application'):
                    val = meta.get(key, '')
                    if val and isinstance(val, str):
                        software_set.add(val)

                for key in ('Author', 'creator', 'lastModifiedBy', 'Creator', 'Artist',
                            'CameraOwnerName'):
                    val = meta.get(key, '')
                    if val and isinstance(val, str) and '@' not in val:
                        authors.add(val)

                for key in ('Company', 'Manager', 'XMP_dc:creator'):
                    val = meta.get(key, '')
                    if val and isinstance(val, str):
                        orgs_set.add(val)

                # Email addresses in metadata values
                all_text = ' '.join(str(v) for v in meta.values())
                found_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', all_text)
                emails_set.update(found_emails)
                if found_emails:
                    entry['sensitive'] = True
                    entry['sensitive_items'].append(f"Emails in metadata: {found_emails}")

                # GPS coordinates
                if 'GPS' in meta or 'GPSLatitude' in meta:
                    gps_count += 1
                    entry['sensitive'] = True
                    entry['sensitive_items'].append("GPS coordinates found in EXIF")

                # Internal usernames / machine names (heuristic)
                for key in ('lastModifiedBy', 'Author', 'creator'):
                    val = meta.get(key, '')
                    if val and re.match(r'^[A-Z][A-Z0-9]{1,20}\\[A-Za-z0-9._-]+$', str(val)):
                        entry['sensitive'] = True
                        entry['sensitive_items'].append(f"Internal domain username: {val}")

                if entry['sensitive']:
                    results['sensitive_findings'].append(entry)

            results['extracted_metadata'].append(entry)

        except Exception as e:
            logger.warning(f"[METADATA] Error processing {file_url}: {e}")

    # Finalize summary
    results['summary']['unique_authors'] = list(authors)[:20]
    results['summary']['unique_software'] = list(software_set)[:20]
    results['summary']['gps_coordinates_found'] = gps_count
    results['summary']['emails_found'] = list(emails_set)[:20]
    results['summary']['organizations_found'] = list(orgs_set)[:10]

    elapsed = round(time.time() - start_time, 2)
    results['elapsed_seconds'] = elapsed
    logger.info(
        f"[METADATA] Done in {elapsed}s. "
        f"Files: {results['files_discovered']}, "
        f"With metadata: {results['files_with_metadata']}, "
        f"Sensitive: {len(results['sensitive_findings'])}"
    )
    return results
