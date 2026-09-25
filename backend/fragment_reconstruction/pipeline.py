"""
fragment_reconstruction/pipeline.py
===================================
End-to-End Intelligent Fragment Reconstruction Pipeline.

Orchestrates all Phase 2 stages:
  1. Fragment Extraction & Ingestion
  2. Fragment Feature Analysis (entropy, byte stats, format markers)
  3. Boundary Analysis & Decomposed Edge Scoring
  4. Reconstruction Graph Construction
  5. Multi-Candidate Constrained Path Search
  6. Actual Byte Reassembly & Concatenation
  7. Format Validation & Corruption/Missing Detection
  8. Forensic Artifact Output Generation (reconstructed.bin, provenance, validation, report)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import Fragment, ReconstructionResult
from .feature_extractor import analyze_fragment
from .boundary_analyzer import BoundaryAnalyzer
from .graph import ReconstructionGraph
from .path_search import PathSearcher
from .reassembler import Reassembler


class FragmentReconstructionPipeline:
    """
    High-level orchestrator for the forensic reconstruction pipeline.
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        weight_signature: float = 0.25,
        weight_continuity: float = 0.30,
        weight_structural: float = 0.25,
        weight_filesystem: float = 0.10,
        weight_entropy: float = 0.10,
        beam_width: int = 10,
        min_edge_score: float = 0.20,
    ):
        self.output_dir = output_dir or (Path(__file__).parent / "output")
        self.boundary_analyzer = BoundaryAnalyzer(
            weight_signature=weight_signature,
            weight_continuity=weight_continuity,
            weight_structural=weight_structural,
            weight_filesystem=weight_filesystem,
            weight_entropy=weight_entropy,
        )
        self.beam_width = beam_width
        self.min_edge_score = min_edge_score
        self.reassembler = Reassembler(output_dir=self.output_dir)

    def run(
        self,
        fragments_input: List[Union[Fragment, bytes, Dict[str, Any]]],
        target_format: str = "UNKNOWN",
        reconstruction_id: Optional[str] = None,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> ReconstructionResult:
        """
        Execute end-to-end fragment reconstruction.
        """
        start_time = time.time()
        rec_id = reconstruction_id or f"REC-{int(start_time * 1000)}"

        # ── 1. Ingest & Analyze Fragments ─────────────────────────────────────
        normalized_fragments: List[Fragment] = []
        for idx, item in enumerate(fragments_input):
            if isinstance(item, Fragment):
                normalized_fragments.append(item)
            elif isinstance(item, bytes):
                frag = analyze_fragment(
                    data=item,
                    fragment_id=f"FRAG-{idx+1:03d}",
                    source_offset=idx * len(item),
                )
                normalized_fragments.append(frag)
            elif isinstance(item, dict):
                data = item.get("data") or item.get("data_bytes")
                if isinstance(data, str):
                    try:
                        data = bytes.fromhex(data)
                    except ValueError:
                        data = data.encode("utf-8")
                elif not isinstance(data, bytes):
                    data = b""

                frag = analyze_fragment(
                    data=data,
                    fragment_id=item.get("fragment_id") or f"FRAG-{idx+1:03d}",
                    source_offset=item.get("source_offset", 0),
                    cluster_index=item.get("cluster_index"),
                    allocation_state=item.get("allocation_state", "UNKNOWN"),
                    source_evidence=item.get("source_evidence", {}),
                )
                normalized_fragments.append(frag)

        if not normalized_fragments:
            return self.reassembler.reassemble_and_validate(
                graph=ReconstructionGraph(self.boundary_analyzer),
                candidate_paths=[],
                target_format=target_format,
                reconstruction_id=rec_id,
                source_metadata=source_metadata,
            )

        # ── 2. Build Reconstruction Graph ─────────────────────────────────────
        graph = ReconstructionGraph(analyzer=self.boundary_analyzer)
        for frag in normalized_fragments:
            graph.add_fragment(frag)

        graph.build_edges(score_threshold=self.min_edge_score)

        # ── 3. Search Candidate Paths (Preserving Multi-Candidate Ambiguity) ─
        searcher = PathSearcher(
            graph=graph,
            beam_width=self.beam_width,
            min_edge_score=self.min_edge_score,
        )
        candidate_paths = searcher.search_candidate_paths()

        # ── 4. Actual Byte Reassembly, Validation & Reporting ─────────────────
        result = self.reassembler.reassemble_and_validate(
            graph=graph,
            candidate_paths=candidate_paths,
            target_format=target_format,
            reconstruction_id=rec_id,
            source_metadata=source_metadata,
        )

        return result


def reconstruct_fragments(
    fragments: List[Union[Fragment, bytes, Dict[str, Any]]],
    target_format: str = "UNKNOWN",
    output_dir: Optional[Path] = None,
    reconstruction_id: Optional[str] = None,
    source_metadata: Optional[Dict[str, Any]] = None,
) -> ReconstructionResult:
    """Convenience functional interface."""
    pipeline = FragmentReconstructionPipeline(output_dir=output_dir)
    return pipeline.run(
        fragments_input=fragments,
        target_format=target_format,
        reconstruction_id=reconstruction_id,
        source_metadata=source_metadata,
    )
