"""FastAPI firmware image assembly service."""

from __future__ import annotations

import base64

from fastapi import Body, FastAPI
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from .hex_parser import ParseResult, parse_intel_hex
from .layout import Region, region_definition_violations, validate_layout
from .relocation import plan_relocation

app = FastAPI(
    title="Firmware Image Assembly Service",
    version="1.0.0",
    description=(
        "Accepts Intel HEX text, validates every record (byte count and "
        "two's-complement checksum; record types 00/01/02/03/04/05), assembles "
        "the firmware image and returns contiguous Base64 segments, "
        "inter-segment gaps, the entry address and per-line diagnostics. "
        "The assembled image can also be validated against a set of named, "
        "non-overlapping memory regions (data/entry permissions, per-region "
        "occupancy and utilization), or relocated as a whole by a single "
        "integer delta constrained by those regions."
    ),
)


class AssembleRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    )
                }
            ]
        }
    }


class DiagnosticOut(BaseModel):
    line: int = Field(..., description="1-based line number; 0 marks a file-level issue")
    status: str = Field(..., description="ok | warning | error")
    record_type: str | None = None
    address: int | None = Field(None, description="Absolute address the record refers to, if any")
    byte_count: int | None = None
    message: str


class SegmentOut(BaseModel):
    start: int = Field(..., description="Absolute start address")
    end: int = Field(..., description="Exclusive end address")
    size: int
    data_base64: str = Field(..., description="Base64-encoded contiguous bytes")


class GapOut(BaseModel):
    start: int = Field(..., description="First unwritten address after the previous segment")
    end: int = Field(..., description="Start address of the next segment (exclusive)")
    size: int


class AssembleResponse(BaseModel):
    ok: bool = Field(..., description="True when no error-level diagnostic was raised")
    error_count: int
    warning_count: int
    entry_address: int | None = Field(None, description="From the last 03/05 record, if present")
    total_bytes: int
    segment_count: int
    segments: list[SegmentOut]
    gaps: list[GapOut]
    diagnostics: list[DiagnosticOut]


class RegionIn(BaseModel):
    name: str = Field(..., min_length=1, description="Region label")
    start: int = Field(..., ge=0, description="Inclusive start address")
    end: int = Field(..., ge=0, description="Exclusive end address (half-open interval)")
    allow_data: bool = Field(True, description="Whether firmware bytes may occupy this region")
    allow_entry: bool = Field(False, description="Whether the entry address may land in this region")


class ValidateLayoutRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    regions: list[RegionIn] = Field(
        ..., description="Memory regions; must be non-empty, non-overlapping half-open intervals"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":020000040800F2\n"
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":04000005080001C12D\n"
                        ":00000001FF\n"
                    ),
                    "regions": [
                        {
                            "name": "flash",
                            "start": 134217728,
                            "end": 134479872,
                            "allow_data": True,
                            "allow_entry": True,
                        },
                        {
                            "name": "config",
                            "start": 134479872,
                            "end": 134484992,
                            "allow_data": True,
                            "allow_entry": False,
                        },
                    ],
                }
            ]
        }
    }


class ViolationOut(BaseModel):
    kind: str = Field(
        ...,
        description=(
            "uncovered_data | data_not_allowed | entry_uncovered | "
            "entry_not_allowed | invalid_region | region_overlap"
        ),
    )
    message: str
    start: int | None = Field(None, description="First affected address, if applicable")
    end: int | None = Field(None, description="Exclusive end of the affected range, if applicable")
    region: str | None = Field(None, description="Region the violation is tied to, if any")


class RegionReportOut(BaseModel):
    name: str
    start: int
    end: int
    size: int
    allow_data: bool
    allow_entry: bool
    occupied_bytes: int = Field(..., description="Firmware bytes that fall inside this region")
    utilization: float = Field(..., description="occupied_bytes / size (0 for empty regions)")
    violations: list[ViolationOut]


class ValidateLayoutResponse(BaseModel):
    ok: bool = Field(..., description="True when the HEX is valid and no layout violation was found")
    hex_ok: bool = Field(..., description="True when the Intel HEX text passed validation")
    regions_valid: bool | None = Field(
        ...,
        description="True when region definitions are non-empty and non-overlapping; "
        "null when the layout check did not run (invalid HEX)",
    )
    error_count: int
    warning_count: int
    entry_address: int | None = Field(None, description="From the last 03/05 record, if present")
    total_bytes: int
    regions: list[RegionReportOut]
    violations: list[ViolationOut] = Field(
        ..., description="Every violation, including uncovered ranges (region = null)"
    )
    diagnostics: list[DiagnosticOut]


class PlanRelocationRequest(BaseModel):
    hex_text: str = Field(..., description="Intel HEX text, one record per line")
    regions: list[RegionIn] = Field(
        ..., description="Memory regions; must be non-empty, non-overlapping half-open intervals"
    )
    max_abs_shift: int | None = Field(
        None,
        ge=0,
        description="Optional bound on |delta|; deltas with a larger absolute shift are rejected",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hex_text": (
                        ":10000000214601360121470136007EFE09D2190141\n"
                        ":0400000500000001F6\n"
                        ":00000001FF\n"
                    ),
                    "regions": [
                        {
                            "name": "current",
                            "start": 0,
                            "end": 65536,
                            "allow_data": False,
                            "allow_entry": False,
                        },
                        {
                            "name": "target",
                            "start": 134217728,
                            "end": 134283264,
                            "allow_data": True,
                            "allow_entry": True,
                        },
                    ],
                    "max_abs_shift": 268435456,
                }
            ]
        }
    }


class DeltaRangeOut(BaseModel):
    lo: int = Field(..., description="Inclusive lower bound of a feasible delta interval")
    hi: int = Field(..., description="Inclusive upper bound of a feasible delta interval")
    size: int = Field(..., description="Number of integer deltas in the interval (hi - lo + 1)")


class RelocatedSegmentOut(SegmentOut):
    pass


class PlanRelocationResponse(BaseModel):
    ok: bool = Field(
        ...,
        description="True when the HEX is valid, regions are sound and a feasible delta exists",
    )
    hex_ok: bool = Field(..., description="True when the Intel HEX text passed validation")
    regions_valid: bool | None = Field(
        ...,
        description="True when region definitions are non-empty and non-overlapping; "
        "null when the check did not run (invalid HEX)",
    )
    feasible: bool = Field(..., description="True when at least one integer delta satisfies every constraint")
    delta: int | None = Field(
        None,
        description="Chosen integer shift (smallest |delta|, then smallest value); null when infeasible",
    )
    max_abs_shift: int | None = Field(None, description="Effective |delta| bound used during planning")
    error_count: int
    warning_count: int
    entry_address: int | None = Field(None, description="Original entry address from the last 03/05 record")
    relocated_entry_address: int | None = Field(
        None, description="Entry address after applying delta; null when infeasible or no entry"
    )
    total_bytes: int
    feasible_delta_ranges: list[DeltaRangeOut] = Field(
        ..., description="Merged closed integer intervals containing every feasible delta"
    )
    segments: list[RelocatedSegmentOut] = Field(
        ..., description="Segments after applying delta; empty when infeasible or input has none"
    )
    violations: list[ViolationOut] = Field(
        ..., description="Region definition violations; planning does not run when non-empty"
    )
    diagnostics: list[DiagnosticOut]



def _build_response(result: ParseResult) -> AssembleResponse:
    return AssembleResponse(
        ok=result.ok,
        error_count=result.error_count,
        warning_count=result.warning_count,
        entry_address=result.entry_address,
        total_bytes=result.total_bytes,
        segment_count=len(result.segments),
        segments=[
            SegmentOut(
                start=s.start,
                end=s.end,
                size=len(s.data),
                data_base64=base64.b64encode(s.data).decode("ascii"),
            )
            for s in result.segments
        ],
        gaps=[GapOut(start=g.start, end=g.end, size=g.size) for g in result.gaps],
        diagnostics=[DiagnosticOut(**vars(d)) for d in result.diagnostics],
    )


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/assemble", response_model=AssembleResponse, tags=["assemble"])
def assemble(request: AssembleRequest) -> AssembleResponse:
    """Assemble a firmware image from Intel HEX text sent as JSON."""
    return _build_response(parse_intel_hex(request.hex_text))


@app.post("/api/v1/assemble/raw", response_model=AssembleResponse, tags=["assemble"])
def assemble_raw(hex_text: str = Body(..., media_type="text/plain")) -> AssembleResponse:
    """Assemble a firmware image from a raw Intel HEX text body (text/plain)."""
    return _build_response(parse_intel_hex(hex_text))


@app.post("/api/v1/validate-layout", response_model=ValidateLayoutResponse, tags=["layout"])
def validate_layout_route(request: ValidateLayoutRequest) -> ValidateLayoutResponse:
    """Validate an Intel HEX image against named memory regions.

    When the HEX text fails validation only parse diagnostics are returned
    (``regions``/``violations`` empty, ``regions_valid`` null). Otherwise the
    contiguous firmware segments are split at region boundaries and checked
    for coverage, ``allow_data``/``allow_entry`` permissions, and per-region
    occupancy is reported.
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    parse_fields = dict(
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        entry_address=parsed.entry_address,
        total_bytes=parsed.total_bytes,
        diagnostics=diagnostics,
    )
    if not parsed.ok:
        return ValidateLayoutResponse(
            ok=False,
            hex_ok=False,
            regions_valid=None,
            regions=[],
            violations=[],
            **parse_fields,
        )

    layout = validate_layout(
        parsed.segments,
        parsed.entry_address,
        [
            Region(
                name=r.name,
                start=r.start,
                end=r.end,
                allow_data=r.allow_data,
                allow_entry=r.allow_entry,
            )
            for r in request.regions
        ],
    )
    return ValidateLayoutResponse(
        ok=layout.ok,
        hex_ok=True,
        regions_valid=layout.regions_valid,
        regions=[
            RegionReportOut(
                name=rep.region.name,
                start=rep.region.start,
                end=rep.region.end,
                size=rep.region.size,
                allow_data=rep.region.allow_data,
                allow_entry=rep.region.allow_entry,
                occupied_bytes=rep.occupied_bytes,
                utilization=rep.utilization,
                violations=[ViolationOut(**vars(v)) for v in rep.violations],
            )
            for rep in layout.reports
        ],
        violations=[ViolationOut(**vars(v)) for v in layout.violations],
        **parse_fields,
    )


@app.post("/api/v1/plan-relocation", response_model=PlanRelocationResponse, tags=["layout"])
def plan_relocation_route(request: PlanRelocationRequest) -> PlanRelocationResponse:
    """Plan a whole-image relocation under one common integer ``delta``.

    Every firmware byte and the entry address are shifted by the same
    integer delta, so inter-segment distances are preserved. A delta is
    feasible only when every segment lies completely inside
    ``allow_data`` regions, the entry lands in an ``allow_entry`` region,
    all resulting addresses are 32-bit, and (optionally)
    ``|delta| <= max_abs_shift``. All feasible closed delta intervals are
    reported after merging; the chosen delta has the smallest absolute
    value (ties prefer the smaller value). Invalid HEX text or invalid
    region definitions return diagnostics and no plan
    (``feasible=false``).
    """
    parsed = parse_intel_hex(request.hex_text)
    diagnostics = [DiagnosticOut(**vars(d)) for d in parsed.diagnostics]
    parse_fields = dict(
        error_count=parsed.error_count,
        warning_count=parsed.warning_count,
        entry_address=parsed.entry_address,
        total_bytes=parsed.total_bytes,
        diagnostics=diagnostics,
    )
    if not parsed.ok:
        return PlanRelocationResponse(
            ok=False,
            hex_ok=False,
            regions_valid=None,
            feasible=False,
            delta=None,
            max_abs_shift=request.max_abs_shift,
            relocated_entry_address=None,
            feasible_delta_ranges=[],
            segments=[],
            violations=[],
            **parse_fields,
        )

    regions = [
        Region(
            name=r.name,
            start=r.start,
            end=r.end,
            allow_data=r.allow_data,
            allow_entry=r.allow_entry,
        )
        for r in request.regions
    ]
    definition_violations = region_definition_violations(regions)
    if definition_violations:
        return PlanRelocationResponse(
            ok=False,
            hex_ok=True,
            regions_valid=False,
            feasible=False,
            delta=None,
            max_abs_shift=request.max_abs_shift,
            relocated_entry_address=None,
            feasible_delta_ranges=[],
            segments=[],
            violations=[ViolationOut(**vars(v)) for v in definition_violations],
            **parse_fields,
        )

    plan = plan_relocation(
        parsed.segments,
        parsed.entry_address,
        regions,
        max_abs_shift=request.max_abs_shift,
    )
    return PlanRelocationResponse(
        ok=plan.feasible,
        hex_ok=True,
        regions_valid=True,
        feasible=plan.feasible,
        delta=plan.delta,
        max_abs_shift=request.max_abs_shift,
        relocated_entry_address=plan.entry_address,
        feasible_delta_ranges=[
            DeltaRangeOut(lo=rng.lo, hi=rng.hi, size=rng.size) for rng in plan.feasible_ranges
        ],
        segments=[
            RelocatedSegmentOut(
                start=s.start,
                end=s.end,
                size=len(s.data),
                data_base64=base64.b64encode(s.data).decode("ascii"),
            )
            for s in plan.segments
        ],
        violations=[],
        **parse_fields,
    )
