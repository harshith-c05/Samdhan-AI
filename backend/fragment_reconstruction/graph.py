"""
fragment_reconstruction/graph.py
================================
Stage 5 — Reconstruction Graph.

Constructs and manages directed evidence graph where:
  - Nodes represent individual forensic fragments
  - Directed edges represent explainable predecessor -> successor transitions
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from .models import Fragment, FragmentEdge, EdgeScoreBreakdown
from .boundary_analyzer import BoundaryAnalyzer


class ReconstructionGraph:
    """
    Evidence-based directed graph for forensic fragment reassembly.
    """

    def __init__(self, analyzer: Optional[BoundaryAnalyzer] = None):
        self.nodes: Dict[str, Fragment] = {}
        self.edges: Dict[Tuple[str, str], FragmentEdge] = {}
        self.outgoing: Dict[str, List[FragmentEdge]] = {}
        self.incoming: Dict[str, List[FragmentEdge]] = {}
        self.analyzer = analyzer or BoundaryAnalyzer()

    def add_fragment(self, frag: Fragment) -> None:
        """Add a fragment node to the graph."""
        self.nodes[frag.fragment_id] = frag
        if frag.fragment_id not in self.outgoing:
            self.outgoing[frag.fragment_id] = []
        if frag.fragment_id not in self.incoming:
            self.incoming[frag.fragment_id] = []

    def build_edges(self, score_threshold: float = 0.20) -> None:
        """
        Evaluate pairwise boundary evidence between all fragment pairs
        and instantiate directed edges above the score threshold.
        """
        frag_list = list(self.nodes.values())
        for a in frag_list:
            for b in frag_list:
                if a.fragment_id == b.fragment_id:
                    continue

                breakdown = self.analyzer.evaluate_edge(a, b)
                if breakdown.final_score >= score_threshold:
                    edge = FragmentEdge(
                        source_id=a.fragment_id,
                        target_id=b.fragment_id,
                        score=breakdown,
                    )
                    self.edges[(a.fragment_id, b.fragment_id)] = edge
                    self.outgoing[a.fragment_id].append(edge)
                    self.incoming[b.fragment_id].append(edge)

        # Sort adjacency lists descending by final_score
        for src in self.outgoing:
            self.outgoing[src].sort(key=lambda e: e.score.final_score, reverse=True)
        for tgt in self.incoming:
            self.incoming[tgt].sort(key=lambda e: e.score.final_score, reverse=True)

    def get_candidate_starts(self) -> List[Fragment]:
        """
        Identify starting fragment candidates:
          1. Fragments containing format headers (header_compatibility == True)
          2. Fragments with zero valid incoming edges
        """
        header_nodes = [f for f in self.nodes.values() if f.header_compatibility]
        if header_nodes:
            return header_nodes

        # Fall back to root nodes (no incoming edges with high score)
        roots = []
        for fid, f in self.nodes.items():
            inc = self.incoming.get(fid, [])
            if not inc or all(e.score.final_score < 0.40 for e in inc):
                roots.append(f)

        return roots if roots else list(self.nodes.values())

    def get_candidate_ends(self) -> List[Fragment]:
        """
        Identify terminal fragment candidates:
          1. Fragments containing format footers (footer_compatibility == True)
          2. Fragments with zero outgoing edges
        """
        footer_nodes = [f for f in self.nodes.values() if f.footer_compatibility]
        if footer_nodes:
            return footer_nodes

        leaves = []
        for fid, f in self.nodes.items():
            out = self.outgoing.get(fid, [])
            if not out or all(e.score.final_score < 0.40 for e in out):
                leaves.append(f)

        return leaves if leaves else list(self.nodes.values())
