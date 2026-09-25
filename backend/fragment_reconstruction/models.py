"""
fragment_reconstruction/models.py
==================================
Data models for Intelligent Fragment Reconstruction (Phase 2).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FormatType(str, Enum):
    JPEG = "JPEG"
    PNG = "PNG"
    PDF = "PDF"
    ZIP = "ZIP"
    DOCX = "DOCX"
    UNKNOWN = "UNKNOWN"


class ReconstructionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    CORRUPTED = "CORRUPTED"
    FAILED = "FAILED"


class AllocationState(str, Enum):
    ALLOCATED = "ALLOCATED"
    UNALLOCATED = "UNALLOCATED"
    UNKNOWN = "UNKNOWN"


class Fragment(BaseModel):
    """
    Forensic model for an individual file fragment extracted from
    disk, memory, or unallocated storage runs.
    """
    fragment_id: str
    source_offset: int = 0
    length: int = 0
    sha256: str = ""
    first_bytes: str = ""           # Hex representation of first 16-32 bytes
    last_bytes: str = ""            # Hex representation of last 16-32 bytes
    entropy: float = 0.0            # Shannon entropy [0.0 - 8.0]
    byte_frequency: List[int] = Field(default_factory=lambda: [0] * 256)
    zero_byte_ratio: float = 0.0    # Ratio of 0x00 bytes
    printable_byte_ratio: float = 0.0 # Ratio of printable ASCII bytes
    format: str = "UNKNOWN"         # Inferred or confirmed format
    header_compatibility: bool = False # Contains valid format file header
    footer_compatibility: bool = False # Contains valid format file footer
    internal_markers: List[str] = Field(default_factory=list) # Markers identified inside
    cluster_index: Optional[int] = None
    allocation_state: str = "UNKNOWN"
    source_evidence: Dict[str, Any] = Field(default_factory=dict)

    # In-memory raw bytes (optional, not serialized if empty/None)
    data_bytes: Optional[bytes] = Field(default=None, exclude=True)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def get_raw_data(self) -> bytes:
        if self.data_bytes is not None:
            return self.data_bytes
        # Fall back to source evidence if hex provided
        hex_data = self.source_evidence.get("raw_hex")
        if hex_data:
            return bytes.fromhex(hex_data)
        return b""


class EdgeScoreBreakdown(BaseModel):
    """
    Fully explainable scoring breakdown for directed edge Fragment A -> Fragment B.
    Never display only 'AI confidence = 91%'. The UI/API must explain WHY.
    """
    signature_compatibility: float = Field(0.0, description="Format compatibility between A and B")
    continuity_compatibility: float = Field(0.0, description="Boundary byte & marker continuity")
    structural_compatibility: float = Field(0.0, description="Parser state & chunk/segment satisfaction")
    filesystem_block_evidence: float = Field(0.0, description="Cluster adjacency / sector order evidence")
    entropy_compatibility: float = Field(0.0, description="Payload entropy distribution consistency")
    contradiction_penalty: float = Field(0.0, description="Penalty for impossible transitions (0.0=none, 1.0=fatal)")
    final_score: float = Field(0.0, description="Composite weighted edge score")
    reasons: List[str] = Field(default_factory=list, description="Explicit human-readable explanations")


class FragmentEdge(BaseModel):
    """Directed edge in the reconstruction graph indicating A precedes B."""
    source_id: str
    target_id: str
    score: EdgeScoreBreakdown


class MissingFragment(BaseModel):
    """Describes a detected gap where data was lost/omitted."""
    after_fragment_id: str
    expected_offset: int
    estimated_size: Optional[int] = None
    expected_structure: str = ""
    description: str = ""


class CorruptRegion(BaseModel):
    """Describes detected byte damage within a fragment."""
    fragment_id: str
    byte_offset_start: int
    byte_offset_end: int
    error_type: str
    details: str
    repair_performed: bool = False


class CandidatePath(BaseModel):
    """One candidate reassembly path through the fragment graph."""
    candidate_id: str
    fragment_ids: List[str]
    path_score: float
    validation_score: float = 0.0
    is_valid: bool = False
    validation_details: Dict[str, Any] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)


class ReconstructionResult(BaseModel):
    """Complete output of the reconstruction pipeline."""
    reconstruction_id: str
    target_format: str
    status: ReconstructionStatus
    total_fragments: int
    selected_path: List[str]
    byte_coverage: int
    output_sha256: Optional[str] = None
    output_filename: str = "reconstructed.bin"
    output_path: Optional[str] = None
    edge_evidence: List[FragmentEdge] = Field(default_factory=list)
    candidates_evaluated: List[CandidatePath] = Field(default_factory=list)
    missing_fragments: List[MissingFragment] = Field(default_factory=list)
    corrupt_regions: List[CorruptRegion] = Field(default_factory=list)
    validation: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    execution_time_s: float = 0.0
