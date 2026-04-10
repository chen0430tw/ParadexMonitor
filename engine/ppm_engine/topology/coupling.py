"""
Module coupling analysis — measure how tightly functions are related
based on shared callees, shared callers, and structural similarity.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ppm_engine.topology.callgraph import CallGraph


def coupling_matrix(graph: CallGraph) -> dict[tuple[int, int], float]:
    """Compute pairwise coupling scores for functions in the call graph.

    Coupling between two functions A and B is based on:
      - Shared callees: functions they both call (Jaccard similarity on call sets)
      - Shared callers: functions that call both of them (Jaccard similarity on called_by sets)

    The final score is: 0.6 * callee_similarity + 0.4 * caller_similarity

    Returns:
        {(addr_a, addr_b): score} for all pairs where score > 0.
        Pairs are stored with addr_a < addr_b to avoid duplicates.
    """
    # Only consider non-import functions that have at least one call or caller
    addrs = [
        addr for addr, fn in graph.functions.items()
        if not fn.is_import and (fn.calls or fn.called_by)
    ]
    addrs.sort()

    result: dict[tuple[int, int], float] = {}

    # Pre-compute sets for performance
    call_sets: dict[int, set[int]] = {}
    caller_sets: dict[int, set[int]] = {}
    for addr in addrs:
        fn = graph.functions[addr]
        call_sets[addr] = set(fn.calls)
        caller_sets[addr] = set(fn.called_by)

    for i in range(len(addrs)):
        a = addrs[i]
        calls_a = call_sets[a]
        callers_a = caller_sets[a]

        for j in range(i + 1, len(addrs)):
            b = addrs[j]
            calls_b = call_sets[b]
            callers_b = caller_sets[b]

            # Jaccard similarity on callees
            callee_union = calls_a | calls_b
            callee_score = 0.0
            if callee_union:
                callee_score = len(calls_a & calls_b) / len(callee_union)

            # Jaccard similarity on callers
            caller_union = callers_a | callers_b
            caller_score = 0.0
            if caller_union:
                caller_score = len(callers_a & callers_b) / len(caller_union)

            score = 0.6 * callee_score + 0.4 * caller_score
            if score > 0:
                result[(a, b)] = round(score, 4)

    return result


def cluster_functions(
    graph: CallGraph, threshold: float = 0.3
) -> list[list[int]]:
    """Group tightly-coupled functions into clusters.

    Uses a simple greedy single-linkage approach:
    1. Compute coupling matrix
    2. Sort pairs by score descending
    3. Merge pairs with coupling > threshold into the same cluster

    Returns:
        List of clusters, each cluster is a list of function addresses.
        Functions not in any cluster are returned as singleton clusters.
    """
    matrix = coupling_matrix(graph)

    # Filter and sort by score descending
    pairs = [(pair, score) for pair, score in matrix.items() if score >= threshold]
    pairs.sort(key=lambda x: x[1], reverse=True)

    # Union-Find for clustering
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        if x not in parent:
            parent[x] = x
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Merge pairs above threshold
    for (a, b), _score in pairs:
        union(a, b)

    # Collect clusters
    clusters_map: dict[int, list[int]] = {}
    # Include all non-import functions
    all_addrs = [
        addr for addr, fn in graph.functions.items()
        if not fn.is_import
    ]

    for addr in all_addrs:
        root = find(addr)
        clusters_map.setdefault(root, []).append(addr)

    # Sort addresses within each cluster and sort clusters by first address
    result = [sorted(members) for members in clusters_map.values()]
    result.sort(key=lambda c: c[0])
    return result
