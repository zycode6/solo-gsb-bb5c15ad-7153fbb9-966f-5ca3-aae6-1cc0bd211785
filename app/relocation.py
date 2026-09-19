"""Whole-image relocation planning.

Given the assembled firmware segments, the entry address and a set of
validated memory regions, find every integer ``delta`` that relocates the
*entire* image by adding the same ``delta`` to every address (segments and
entry alike), so inter-segment distances are preserved.

A delta is feasible exactly when:

* every firmware segment, shifted by delta, lies completely inside the
  union of regions with ``allow_data=true`` (it may straddle a boundary
  where two such regions touch or overlap);
* the entry address (when present), shifted by delta, lies in a region
  with ``allow_entry=true``;
* every shifted address stays inside the unsigned 32-bit range
  ``[0, 0xFFFFFFFF]``;
* ``|delta| <= max_abs_shift`` when that bound is supplied.

For every constraint the set of allowed deltas is a closed integer
interval; intersecting them all yields the feasible set, which is merged
into disjoint closed intervals.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hex_parser import Segment
from .layout import Region

ADDR_MIN = 0
ADDR_MAX = 0xFFFFFFFF


@dataclass
class Interval:
    """A closed integer interval ``[lo, hi]`` (``lo <= hi``)."""

    lo: int
    hi: int

    @property
    def size(self) -> int:
        """Number of integer points in the interval."""
        return self.hi - self.lo + 1


@dataclass
class RelocationPlan:
    feasible: bool
    feasible_ranges: list[Interval] = field(default_factory=list)
    delta: int | None = None
    segments: list[Segment] = field(default_factory=list)
    entry_address: int | None = None


def _merge_components(regions: list[Region]) -> list[tuple[int, int]]:
    """Merge overlapping/touching allow_data regions into [lo, hi] windows."""
    windows = sorted((r.start, r.end - 1) for r in regions if r.allow_data)
    merged: list[list[int]] = []
    for lo, hi in windows:
        if not merged or lo > merged[-1][1] + 1:
            merged.append([lo, hi])
        elif hi > merged[-1][1]:
            merged[-1][1] = hi
    return [(lo, hi) for lo, hi in merged]


def _merge_ranges(ranges: list[Interval]) -> list[Interval]:
    """Merge overlapping/touching closed integer intervals."""
    ordered = sorted(ranges, key=lambda i: i.lo)
    merged: list[Interval] = []
    for rng in ordered:
        if not merged or rng.lo > merged[-1].hi + 1:
            merged.append(Interval(rng.lo, rng.hi))
        elif rng.hi > merged[-1].hi:
            merged[-1].hi = rng.hi
    return merged


def _intersect_all(ranges: list[Interval]) -> list[Interval]:
    """Intersect a list of interval unions down to a single interval union.

    Each input is itself a list of disjoint closed intervals (the deltas
    accepted by one constraint). The feasible set is their intersection.
    """
    if not ranges:
        return []
    result: list[Interval] = ranges[0]
    for ranges_b in ranges[1:]:
        crossed: list[Interval] = []
        for a in result:
            for b in ranges_b:
                lo = max(a.lo, b.lo)
                hi = min(a.hi, b.hi)
                if lo <= hi:
                    crossed.append(Interval(lo, hi))
        result = _merge_ranges(crossed)
        if not result:
            break
    return result


def _union_to_ranges(points: list[tuple[int, int]]) -> list[Interval]:
    """Turn accepted [lo, hi] delta windows into merged closed intervals."""
    return _merge_ranges([Interval(lo, hi) for lo, hi in points])


def plan_relocation(
    segments: list[Segment],
    entry_address: int | None,
    regions: list[Region],
    max_abs_shift: int | None = None,
) -> RelocationPlan:
    """Compute the feasible delta set and pick the smallest-magnitude delta.

    ``regions`` are assumed to have passed the definition checks
    (non-empty, non-overlapping).
    """
    data_windows = _merge_components(regions)
    entry_windows = sorted((r.start, r.end - 1) for r in regions if r.allow_entry)

    # One interval-union per constraint; feasible deltas are the intersection.
    constraints: list[list[Interval]] = []

    # Every byte of every segment must end up inside an allow_data window.
    for seg in segments:
        accepted: list[tuple[int, int]] = []
        for lo, hi in data_windows:
            d_lo = lo - seg.start          # seg.start + d >= lo
            d_hi = hi - (seg.end - 1)      # seg.end - 1 + d <= hi
            if d_lo <= d_hi:
                accepted.append((d_lo, d_hi))
        constraints.append(_union_to_ranges(accepted))

    # The entry (if any) must end up at an address covered by allow_entry.
    if entry_address is not None:
        accepted = [
            (lo - entry_address, hi - entry_address) for lo, hi in entry_windows
        ]
        constraints.append(_union_to_ranges(accepted))

    # Shifted addresses must stay within unsigned 32-bit range. Only the
    # firmware's own addresses matter (the tightest lower/upper bound comes
    # from the smallest/highest segment or entry address, respectively).
    firmware_bounds: list[int] = []
    for seg in segments:
        firmware_bounds += [seg.start, seg.end - 1]
    if entry_address is not None:
        firmware_bounds.append(entry_address)
    if firmware_bounds:
        constraints.append(
            [Interval(ADDR_MIN - min(firmware_bounds), ADDR_MAX - max(firmware_bounds))]
        )

    # Optional absolute-shift budget.
    if max_abs_shift is not None:
        constraints.append([Interval(-max_abs_shift, max_abs_shift)])

    if not constraints:
        # Nothing to relocate: only delta 0 is meaningful.
        feasible_ranges = [Interval(0, 0)]
    else:
        feasible_ranges = _intersect_all(constraints)

    if not feasible_ranges:
        return RelocationPlan(feasible=False, feasible_ranges=[], delta=None)

    delta = _select_delta(feasible_ranges)
    relocated = [
        Segment(start=seg.start + delta, data=seg.data) for seg in segments
    ]
    new_entry = entry_address + delta if entry_address is not None else None
    return RelocationPlan(
        feasible=True,
        feasible_ranges=feasible_ranges,
        delta=delta,
        segments=relocated,
        entry_address=new_entry,
    )


def _select_delta(ranges: list[Interval]) -> int:
    """Pick the feasible delta with smallest |delta|; ties prefer the smaller.

    For closed integer intervals the candidates are 0 (when any interval
    contains it) or the endpoint closest to zero.
    """
    candidates: list[int] = []
    for rng in ranges:
        if rng.lo <= 0 <= rng.hi:
            return 0
        candidates.append(rng.lo if rng.lo > 0 else rng.hi)
    return min(candidates, key=lambda d: (abs(d), d))
