"""
disk_recovery/reader.py
=======================
READ-ONLY block/sector reader for disk image files.

SAFETY CONTRACT
---------------
* The image file is ALWAYS opened with mode="rb" (read-only).
* No writes, seeks-for-write, or flushes are ever performed on the source.
* The image SHA-256 is computed on first open and cached.
* All public methods return bytes copies — callers cannot corrupt the source.

Supports:
  - Raw / flat disk images (.img, .raw, .dd, .bin)
  - Extensible: EWF / AFF support can be added later by replacing _open().
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Optional


SECTOR_SIZE = 512  # standard sector size used as default


class ImageReader:
    """
    Read-only accessor for a flat disk image file.

    Usage
    -----
        reader = ImageReader("/path/to/image.img")
        mbr_bytes = reader.read_sectors(0, 1)   # first 512 bytes
        reader.close()

    Context-manager form is preferred:
        with ImageReader("/path/to/image.img") as r:
            data = r.read_bytes(0, 512)
    """

    def __init__(self, image_path: str, sector_size: int = SECTOR_SIZE) -> None:
        self.path = Path(image_path).resolve()
        if not self.path.exists():
            raise FileNotFoundError(f"Image not found: {self.path}")
        if not self.path.is_file():
            raise ValueError(f"Not a regular file: {self.path}")

        self.sector_size = sector_size
        self._fh = open(self.path, "rb")  # READ-ONLY — never "wb", "r+b", etc.
        self._size: int = self.path.stat().st_size
        self._sha256: Optional[str] = None  # computed lazily

    # ── Context-manager support ───────────────────────────────────────────────

    def __enter__(self) -> "ImageReader":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        if self._fh and not self._fh.closed:
            self._fh.close()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def size_bytes(self) -> int:
        return self._size

    @property
    def total_sectors(self) -> int:
        return self._size // self.sector_size

    # ── Core read primitives ──────────────────────────────────────────────────

    def read_bytes(self, offset: int, length: int) -> bytes:
        """
        Read *length* bytes starting at byte *offset*.
        Returns fewer bytes (or b'') if the request exceeds image size.
        Never writes or modifies the source.
        """
        if offset < 0 or offset >= self._size:
            return b""
        length = min(length, self._size - offset)
        self._fh.seek(offset)
        return self._fh.read(length)

    def read_sectors(self, lba: int, count: int = 1) -> bytes:
        """Read *count* sectors starting at logical block address *lba*."""
        return self.read_bytes(lba * self.sector_size, count * self.sector_size)

    # ── SHA-256 of entire image ───────────────────────────────────────────────

    def compute_sha256(self, chunk_size: int = 1 << 20) -> str:
        """
        Compute SHA-256 of the entire image in streaming chunks.
        Result is cached — subsequent calls return instantly.
        """
        if self._sha256 is not None:
            return self._sha256
        h = hashlib.sha256()
        self._fh.seek(0)
        while True:
            chunk = self._fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
        self._sha256 = h.hexdigest()
        return self._sha256

    # ── Convenience helpers ────────────────────────────────────────────────────

    def read_u8(self, offset: int) -> int:
        d = self.read_bytes(offset, 1)
        return d[0] if d else 0

    def read_u16le(self, offset: int) -> int:
        d = self.read_bytes(offset, 2)
        return struct.unpack_from("<H", d)[0] if len(d) >= 2 else 0

    def read_u32le(self, offset: int) -> int:
        d = self.read_bytes(offset, 4)
        return struct.unpack_from("<I", d)[0] if len(d) >= 4 else 0

    def read_u64le(self, offset: int) -> int:
        d = self.read_bytes(offset, 8)
        return struct.unpack_from("<Q", d)[0] if len(d) >= 8 else 0

    def iter_sectors(self, start_lba: int = 0, end_lba: Optional[int] = None,
                     batch: int = 128):
        """
        Yield (lba, data) tuples in batches.
        Useful for signature scanning without loading the whole image into RAM.
        """
        if end_lba is None:
            end_lba = self.total_sectors
        lba = start_lba
        while lba < end_lba:
            count = min(batch, end_lba - lba)
            data = self.read_sectors(lba, count)
            yield lba, data
            lba += count
