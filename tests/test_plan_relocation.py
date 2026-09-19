"""Tests for the /api/v1/plan-relocation endpoint and relocation logic."""

from fastapi.testclient import TestClient

from app.hex_parser import Segment, parse_intel_hex
from app.layout import Region
from app.main import app
from app.relocation import Interval, plan_relocation

client = TestClient(app)


def rec(rectype: int, addr: int, data: bytes = b"") -> str:
    """Build a valid Intel HEX record line."""
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + bytes(data)
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


EOF = rec(0x01, 0)


def data_rec(addr: int, data: bytes) -> str:
    return rec(0x00, addr, data)


def entry_rec(addr: int) -> str:
    return rec(0x05, 0, addr.to_bytes(4, "big"))


def region(name, start, end, allow_data=True, allow_entry=False):
    return {
        "name": name,
        "start": start,
        "end": end,
        "allow_data": allow_data,
        "allow_entry": allow_entry,
    }


# ---------------------------------------------------------------------------
# pure relocation logic
# ---------------------------------------------------------------------------

def test_shifts_whole_image_up_by_common_delta():
    # 16 bytes at [0x00,0x10), entry 0x01. Origin allows data only; the
    # destination window [0x1000,0x1100) allows data and entry.
    parsed = parse_intel_hex(
        "\n".join([data_rec(0x0000, bytes(range(16))), entry_rec(0x01), EOF])
    )
    plan = plan_relocation(
        parsed.segments,
        parsed.entry_address,
        [
            Region("origin", 0x0000, 0x0010, allow_data=True, allow_entry=False),
            Region("dest", 0x1000, 0x1100, allow_data=True, allow_entry=True),
        ],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [Interval(0x1000, 0x10F0)]
    assert plan.delta == 0x1000  # smallest positive delta (|delta| tie order)
    assert plan.segments[0].start == 0x1000
    assert plan.segments[0].end == 0x1010
    assert plan.segments[0].data == bytes(range(16))
    assert plan.entry_address == 0x1001


def test_zero_delta_preferred_when_placement_already_valid():
    parsed = parse_intel_hex(
        "\n".join([data_rec(0x0000, b"\xAA" * 8), entry_rec(0x04), EOF])
    )
    plan = plan_relocation(
        parsed.segments,
        parsed.entry_address,
        [Region("flash", 0x0000, 0x1000, allow_data=True, allow_entry=True)],
    )
    assert plan.feasible
    assert plan.delta == 0
    assert plan.feasible_ranges[0].lo <= 0 <= plan.feasible_ranges[0].hi
    assert plan.segments[0].start == 0
    assert plan.entry_address == 0x04


def test_equal_magnitude_tie_prefers_smaller_negative_delta():
    # One byte at 0x100; the address 0x100 itself is a hole between two
    # windows, so 0 is infeasible while +/- deltas are symmetric.
    seg = Segment(start=0x100, data=b"\x01")
    plan = plan_relocation(
        [seg],
        0x100,
        [
            Region("lo", 0x000, 0x100, allow_data=True, allow_entry=True),
            Region("hi", 0x101, 0x200, allow_data=True, allow_entry=True),
        ],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [Interval(-256, -1), Interval(1, 255)]
    assert plan.delta == -1  # |-1| == |1|, smaller numeric value wins


def test_segment_may_straddle_touching_allow_data_regions():
    # Two touching 8-byte windows behave as one 16-byte window.
    seg = Segment(start=0x00, data=bytes(range(16)))
    plan = plan_relocation(
        [seg],
        None,
        [
            Region("a", 0x1000, 0x1008, allow_data=True),
            Region("b", 0x1008, 0x1010, allow_data=True),
        ],
    )
    assert plan.feasible
    assert plan.feasible_ranges == [Interval(0x1000, 0x1000)]
    assert plan.delta == 0x1000
    assert (plan.segments[0].start, plan.segments[0].end) == (0x1000, 0x1010)


def test_gap_between_data_regions_makes_segment_infeasible():
    seg = Segment(start=0x00, data=bytes(16))
    plan = plan_relocation(
        [seg],
        None,
        [
            Region("a", 0x1000, 0x1008, allow_data=True),
            Region("b", 0x1010, 0x1018, allow_data=True),
        ],
    )
    assert not plan.feasible
    assert plan.feasible_ranges == []
    assert plan.delta is None
    assert plan.segments == []


def test_entry_window_intersects_data_window():
    # Data can move anywhere within a large flash window, but the entry is
    # only accepted in a tiny entry window at [0x2000,0x2010).
    parsed = parse_intel_hex(
        "\n".join([data_rec(0x0000, b"\x01" * 4), entry_rec(0x00), EOF])
    )
    plan = plan_relocation(
        parsed.segments,
        parsed.entry_address,
        [
            Region("flash", 0x0000, 0x10000, allow_data=True, allow_entry=False),
            Region("entry", 0x2000, 0x2010, allow_data=False, allow_entry=True),
        ],
    )
    assert plan.feasible
    # entry 0x00 + d in [0x2000,0x200F]; data [0,4)+d inside [0,0x10000)
    assert plan.feasible_ranges == [Interval(0x2000, 0x200F)]
    assert plan.delta == 0x2000
    assert plan.entry_address == 0x2000


def test_multiple_segments_share_one_delta_and_keep_distance():
    parsed = parse_intel_hex(
        "\n".join(
            [
                data_rec(0x0000, b"\x01" * 4),
                data_rec(0x0100, b"\x02" * 4),
                EOF,
            ]
        )
    )
    assert len(parsed.segments) == 2
    plan = plan_relocation(
        parsed.segments,
        None,
        [Region("dest", 0x1000, 0x2000, allow_data=True)],
    )
    assert plan.feasible
    assert plan.delta == 0x1000
    assert [(s.start, s.end) for s in plan.segments] == [
        (0x1000, 0x1004),
        (0x1100, 0x1104),
    ]
    # inter-segment distance preserved
    assert (
        plan.segments[1].start - plan.segments[0].start
        == parsed.segments[1].start - parsed.segments[0].start
    )


def test_max_abs_shift_bounds_feasible_range():
    parsed = parse_intel_hex(
        "\n".join([data_rec(0x0000, bytes(range(16))), entry_rec(0x01), EOF])
    )
    regions = [Region("dest", 0x1000, 0x1100, allow_data=True, allow_entry=True)]

    within = plan_relocation(parsed.segments, parsed.entry_address, regions, max_abs_shift=0x1000)
    assert within.feasible
    assert within.delta == 0x1000
    assert within.feasible_ranges == [Interval(0x1000, 0x1000)]

    too_small = plan_relocation(parsed.segments, parsed.entry_address, regions, max_abs_shift=0x0FFF)
    assert not too_small.feasible
    assert too_small.delta is None


def test_relocated_addresses_must_stay_32bit():
    # 8 bytes whose last byte is already at 0xFFFFFFFF: only d <= 0 works,
    # even though the data window extends past the 32-bit address space.
    seg = Segment(start=0xFFFFFFF8, data=bytes(8))
    plan = plan_relocation(
        [seg],
        None,
        [Region("space", 0x00000000, 0x100000100, allow_data=True)],
    )
    assert plan.feasible
    assert plan.feasible_ranges[0].hi == 0
    assert plan.delta == 0
    assert plan.segments[0].end - 1 == 0xFFFFFFFF


def test_relocation_window_cannot_extend_past_32bit_space():
    # A window reaching past 0xFFFFFFFF still clips at the 32-bit limit:
    # 16 bytes at the very top of the space can only stay or move down.
    seg = Segment(start=0xFFFFFFF0, data=bytes(16))
    plan = plan_relocation(
        [seg],
        None,
        [Region("space", 0x00000000, 0x100000010, allow_data=True)],
    )
    assert plan.feasible
    assert plan.feasible_ranges[0].hi == 0
    assert plan.delta == 0
    assert plan.segments[0].end - 1 == 0xFFFFFFFF


def test_segment_wider_than_32bit_space_is_infeasible():
    # An image larger than the entire address space can never fit, whatever
    # the regions say.
    huge_start = -(2**31)
    seg = Segment(start=huge_start, data=bytes(2**32 + 4))
    plan = plan_relocation(
        [seg],
        None,
        [Region("space", -(2**33), 2**33, allow_data=True)],
    )
    assert not plan.feasible
    assert plan.feasible_ranges == []


def test_data_only_regions_allow_full_window_for_single_byte():
    seg = Segment(start=0x00, data=b"\x01")
    plan = plan_relocation(
        [seg],
        None,
        [
            Region("data_only", 0x10, 0x20, allow_data=True),
        ],
    )
    assert plan.feasible
    assert plan.entry_address is None
    assert plan.feasible_ranges == [Interval(0x10, 0x1F)]


def test_allow_data_false_region_cannot_hold_bytes():
    seg = Segment(start=0x00, data=b"\x01" * 4)
    plan = plan_relocation(
        [seg],
        None,
        [Region("nodefault", 0x00, 0x10, allow_data=False, allow_entry=True)],
    )
    assert not plan.feasible


def test_empty_image_only_allows_zero_delta():
    plan = plan_relocation([], None, [Region("flash", 0x00, 0x10, allow_data=True)])
    assert plan.feasible
    assert plan.feasible_ranges == [Interval(0, 0)]
    assert plan.delta == 0
    assert plan.segments == []
    assert plan.entry_address is None


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_api_plan_relocation_happy_path():
    text = "\n".join([data_rec(0x0000, bytes(range(16))), entry_rec(0x01), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [
                region("origin", 0x0000, 0x0010, allow_data=True, allow_entry=False),
                region("dest", 0x1000, 0x1100, allow_data=True, allow_entry=True),
            ],
            "max_abs_shift": 0x100000,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["hex_ok"] is True
    assert body["regions_valid"] is True
    assert body["feasible"] is True
    assert body["delta"] == 0x1000
    assert body["feasible_delta_ranges"] == [
        {"lo": 0x1000, "hi": 0x10F0, "size": 0xF1}
    ]
    assert body["entry_address"] == 0x01
    assert body["relocated_entry_address"] == 0x1001
    assert len(body["segments"]) == 1
    seg = body["segments"][0]
    assert (seg["start"], seg["end"], seg["size"]) == (0x1000, 0x1010, 16)
    import base64

    assert base64.b64decode(seg["data_base64"]) == bytes(range(16))
    assert body["violations"] == []
    assert body["error_count"] == 0


def test_api_no_feasible_delta_reports_feasible_false():
    text = "\n".join([data_rec(0x0000, b"\x01" * 16), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("tiny", 0x1000, 0x1008)],  # window smaller than image
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["feasible"] is False
    assert body["hex_ok"] is True
    assert body["regions_valid"] is True
    assert body["delta"] is None
    assert body["feasible_delta_ranges"] == []
    assert body["segments"] == []
    assert body["relocated_entry_address"] is None


def test_api_invalid_hex_returns_diagnostics_and_no_plan():
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": ":00000001FE\n",  # bad checksum
            "regions": [region("flash", 0x00, 0x10, allow_entry=True)],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is False
    assert body["regions_valid"] is None
    assert body["feasible"] is False
    assert body["delta"] is None
    assert body["segments"] == []
    assert body["violations"] == []
    assert any("checksum" in d["message"] for d in body["diagnostics"])


def test_api_overlapping_regions_block_planning():
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": "\n".join([data_rec(0, b"\x01"), EOF]),
            "regions": [region("a", 0x00, 0x10), region("b", 0x08, 0x20)],
        },
    )
    body = resp.json()
    assert body["ok"] is False
    assert body["hex_ok"] is True
    assert body["regions_valid"] is False
    assert body["feasible"] is False
    assert body["feasible_delta_ranges"] == []
    assert [v["kind"] for v in body["violations"]] == ["region_overlap"]


def test_api_invalid_region_interval_blocked():
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": "\n".join([data_rec(0, b"\x01"), EOF]),
            "regions": [region("bad", 0x10, 0x10)],
        },
    )
    body = resp.json()
    assert body["regions_valid"] is False
    assert body["violations"][0]["kind"] == "invalid_region"
    assert body["feasible"] is False


def test_api_max_abs_shift_must_be_non_negative():
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": "\n".join([data_rec(0, b"\x01"), EOF]),
            "regions": [region("flash", 0x00, 0x10)],
            "max_abs_shift": -1,
        },
    )
    assert resp.status_code == 422


def test_api_region_field_validation_still_applies():
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": "\n".join([data_rec(0, b"\x01"), EOF]),
            "regions": [{"name": "", "start": 0, "end": 16}],
        },
    )
    assert resp.status_code == 422


def test_api_boundary_delta_equal_to_max_abs_shift_accepted():
    # Image at [0,1), window [0x100,0x200): feasible deltas [0x100,0x1FF];
    # a budget of exactly 0x100 must leave the single boundary delta.
    text = "\n".join([data_rec(0x0000, b"\x7E"), EOF])
    resp = client.post(
        "/api/v1/plan-relocation",
        json={
            "hex_text": text,
            "regions": [region("dest", 0x100, 0x200)],
            "max_abs_shift": 0x100,
        },
    )
    body = resp.json()
    assert body["feasible"] is True
    assert body["delta"] == 0x100
    assert body["feasible_delta_ranges"] == [{"lo": 0x100, "hi": 0x100, "size": 1}]
