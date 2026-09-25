"""
fragment_reconstruction/path_search.py
======================================
Stage 6 & 8 — Graph Path Search & Multi-Candidate Exploration.

Implements constrained graph search:
  - Identifies candidate start fragments
  - Extends paths using explainable edge scores
  - Strictly prevents cycles and duplicate fragments
  - Prunes impossible sequences early
  - Preserves branch ambiguity: generates multiple viable candidates (Candidate A, B, etc.)
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from .models import CandidatePath, Fragment, FragmentEdge
from .graph import ReconstructionGraph


class PathSearcher:
    """
    Search engine that traverses the ReconstructionGraph to discover
    defensible fragment reassembly orders.
    """

    def __init__(
        self,
        graph: ReconstructionGraph,
        beam_width: int = 10,
        min_edge_score: float = 0.20,
        max_depth: int = 64,
    ):
        self.graph = graph
        self.beam_width = beam_width
        self.min_edge_score = min_edge_score
        self.max_depth = max_depth

    def search_candidate_paths(self) -> List[CandidatePath]:
        """
        Execute path search and return ranked list of CandidatePath objects.
        Preserves ambiguity when multiple viable sequences exist.
        """
        starts = self.graph.get_candidate_starts()
        if not starts:
            return []

        completed_paths: List[Tuple[List[str], float, List[str]]] = []

        # Beam / priority search
        # Each item in frontier is (current_path: List[str], cumulative_score: float, edge_reasons: List[str])
        frontier: List[Tuple[List[str], float, List[str]]] = [
            ([start.fragment_id], 1.0, [f"Root start: {start.fragment_id} (header match={start.header_compatibility})"])
            for start in starts
        ]

        depth = 0
        while frontier and depth < self.max_depth:
            depth += 1
            next_frontier: List[Tuple[List[str], float, List[str]]] = []

            for path, current_score, reasons in frontier:
                last_fid = path[-1]
                last_frag = self.graph.nodes[last_fid]

                # Check if terminal
                if last_frag.footer_compatibility:
                    completed_paths.append((path, current_score, reasons + [f"Terminal footer reached at {last_fid}"]))
                    continue

                outgoing = self.graph.outgoing.get(last_fid, [])
                valid_extensions = []

                for edge in outgoing:
                    tgt_id = edge.target_id
                    # Cycle & duplicate prevention
                    if tgt_id in path:
                        continue
                    # Impossible transition rejection
                    if edge.score.contradiction_penalty >= 0.85:
                        continue
                    if edge.score.final_score < self.min_edge_score:
                        continue

                    valid_extensions.append(edge)

                if not valid_extensions:
                    # Dead end: record current path as terminal/partial
                    completed_paths.append((path, current_score, reasons + ["No further compatible edges; path concluded"]))
                else:
                    # Branch exploration: keep top branching candidates to preserve ambiguity
                    for edge in valid_extensions[:self.beam_width]:
                        new_path = path + [edge.target_id]
                        edge_score = edge.score.final_score
                        # Cumulative score combining path length & geometric/arithmetic progression
                        new_score = current_score * 0.7 + edge_score * 0.3
                        new_reasons = reasons + [
                            f"Edge {last_fid} -> {edge.target_id} (score={edge_score:.3f}): " + "; ".join(edge.score.reasons[:2])
                        ]
                        next_frontier.append((new_path, new_score, new_reasons))

            # Beam pruning: prioritize higher evidence score first, path length second
            next_frontier.sort(key=lambda item: (item[1], len(item[0])), reverse=True)
            frontier = next_frontier[:self.beam_width]

        # Flush any remaining paths in frontier
        for item in frontier:
            completed_paths.append(item)

        # Deduplicate paths
        unique_paths: Dict[Tuple[str, ...], Tuple[float, List[str]]] = {}
        for path, score, reasons in completed_paths:
            t_path = tuple(path)
            if t_path not in unique_paths or unique_paths[t_path][0] < score:
                unique_paths[t_path] = (score, reasons)

        # Sort candidate paths: prefer paths with higher edge score first
        sorted_candidates = sorted(
            unique_paths.items(),
            key=lambda item: (item[1][0], len(item[0])),
            reverse=True,
        )

        candidates: List[CandidatePath] = []
        for idx, (p_tuple, (score, reasons)) in enumerate(sorted_candidates[:self.beam_width]):
            candidates.append(
                CandidatePath(
                    candidate_id=f"CANDIDATE-{chr(65 + idx) if idx < 26 else idx}",
                    fragment_ids=list(p_tuple),
                    path_score=round(score, 4),
                    reasons=reasons,
                )
            )

        return candidates
