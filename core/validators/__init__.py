"""
core/validators/__init__.py
===========================
Registry of format-specific structural validators.
"""

from typing import Dict, Optional, Type

from core.validators.base import BaseValidator, ValidationResult
from core.validators.docx import DOCXValidator
from core.validators.jpeg import JPEGValidator
from core.validators.log import LogValidator
from core.validators.pdf import PDFValidator
from core.validators.png import PNGValidator
from core.validators.sqlite import SQLiteValidator
from core.validators.zip_validator import ZIPValidator


VALIDATOR_REGISTRY: Dict[str, Type[BaseValidator]] = {
    "JPEG": JPEGValidator,
    "JPG": JPEGValidator,
    "PNG": PNGValidator,
    "PDF": PDFValidator,
    "ZIP": ZIPValidator,
    "DOCX": DOCXValidator,
    "SQLITE": SQLiteValidator,
    "SQLITE3": SQLiteValidator,
    "LOG": LogValidator,
    "TXT": LogValidator,
}


def get_validator_for_format(format_name: str) -> Optional[BaseValidator]:
    """Factory retrieving format validator instance by format key."""
    if not format_name:
        return None
    cls = VALIDATOR_REGISTRY.get(format_name.upper())
    return cls() if cls else None


__all__ = [
    "BaseValidator",
    "ValidationResult",
    "JPEGValidator",
    "PNGValidator",
    "PDFValidator",
    "ZIPValidator",
    "DOCXValidator",
    "SQLiteValidator",
    "LogValidator",
    "VALIDATOR_REGISTRY",
    "get_validator_for_format",
]
