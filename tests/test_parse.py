"""Original synthetic parser controls; never independent held-out Gold."""

import pytest

from dev_logs_mcp.parse import ParseState, normalize_time, parse_line


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"),
        ("2026-01-02T03:04:05+02:00", "2026-01-02T01:04:05Z"),
        ("2026-01-02 03:04:05.001", "2026-01-02T03:04:05.001000Z"),
    ],
)
def test_normalize_timestamp(raw, expected):
    """what_bug_this_catches: offset-free and explicit offsets have one UTC meaning."""
    assert normalize_time(raw) == expected


@pytest.mark.parametrize("bad", ["secret-value", "2026-02-31T00:00:00Z", "x" * 65, 123, True])
def test_bad_timestamp_is_value_free(bad):
    with pytest.raises(ValueError, match="^invalid timestamp$"):
        normalize_time(bad)


@pytest.mark.parametrize("alias", ["timestamp", "time", "ts", "@timestamp"])
@pytest.mark.parametrize("level", ["level", "severity", "log_level"])
def test_json_aliases_do_not_unwrap_or_drop_fields(alias, level):
    raw = f'{{"{alias}":"2026-01-02T03:04:05Z","{level}":"warning","nested":{{"x":1}}}}'
    result = parse_line(raw)
    assert result.text == raw
    assert result.state == ParseState("2026-01-02T03:04:05Z", "WARN")
    assert not result.timestamp_inherited and not result.level_inherited


@pytest.mark.parametrize(
    "numeric,level",
    [(10, "TRACE"), (20, "DEBUG"), (30, "INFO"), (40, "WARN"), (50, "ERROR"), (60, "FATAL")],
)
def test_pino_numeric_levels(numeric, level):
    assert parse_line(f'{{"level":{numeric}}}').state.level == level


def test_trace_inheritance_and_nonmonotonic_header():
    """what_bug_this_catches: trace state must not imply temporal monotonicity."""
    first = parse_line("2026-01-02T03:04:05Z [ERROR] failed")
    trace = parse_line("  at example.py:17", first.state)
    older = parse_line("2025-01-01T00:00:00Z INFO older", trace.state)
    assert trace.state == first.state
    assert trace.timestamp_inherited and trace.level_inherited
    assert older.state == ParseState("2025-01-01T00:00:00Z", "INFO")
    assert not older.timestamp_inherited


@pytest.mark.parametrize(
    "raw", ['{"level":true}', '{"level":"secret"}', "{broken", "[1,2]", '{"time":"secret"}']
)
def test_malformed_or_unknown_json_explicit_fallback(raw):
    result = parse_line(raw, format="jsonl")
    assert result.fallback
    assert result.state == ParseState()
    assert result.text == raw
    assert raw not in repr(result)


def test_keyword_error_is_not_classified_without_header():
    assert parse_line("ERROR keyword in an unknown format").state.level is None
    assert parse_line("2026-01-02T03:04:05Z no severity").state.level is None


def test_json_object_does_not_inherit_previous_error():
    """what_bug_this_catches: an unclassified JSON event is not an ERROR continuation."""
    result = parse_line('{"msg":"normal event"}', ParseState("2026-01-01T00:00:00Z", "ERROR"))
    assert result.state == ParseState()
    assert result.fallback and not result.level_inherited


@pytest.mark.parametrize("timestamp", ['"invalid"', '"2026-02-31T00:00:00Z"', "123", "true", '""'])
@pytest.mark.parametrize("format", ["auto", "jsonl"])
def test_invalid_json_timestamp_cannot_inherit_prior_record(timestamp, format):
    """what_bug_this_catches: an invalid JSON date cannot inherit a prior ERROR trace."""
    raw = f'{{"timestamp":{timestamp},"level":"WARN","msg":"synthetic event"}}'
    result = parse_line(raw, ParseState("2026-01-01T00:00:00Z", "ERROR"), format=format)
    assert result.state == ParseState(None, "WARN")
    assert result.fallback and not result.timestamp_inherited and not result.level_inherited
    assert result.text == raw
    following = parse_line("  synthetic continuation", result.state)
    assert following.state == ParseState(None, "WARN")
    assert not following.timestamp_inherited and following.level_inherited


def test_metadata_cannot_echo_arbitrary_json_fields():
    raw = '{"timestamp":"private-marker","level":"private-marker"}'
    result = parse_line(raw)
    assert "private-marker" not in repr(result)
    assert result.state == ParseState()


@pytest.mark.parametrize("format", ["auto", "plain_iso"])
@pytest.mark.parametrize(
    "timestamp", ["2026-02-31T00:00:00Z", "2026-01-01T25:00:00Z", "2026-00-01T00:00:00Z"]
)
@pytest.mark.parametrize("severity,expected", [("WARN", "WARN"), ("UNKNOWN", None)])
def test_invalid_plain_timestamp_starts_its_own_record(format, timestamp, severity, expected):
    """what_bug_this_catches: malformed plain dates cannot inherit a prior ERROR event."""
    raw = f"{timestamp} {severity} synthetic event"
    result = parse_line(raw, ParseState("2026-01-01T00:00:00Z", "ERROR"), format=format)
    assert result.state == ParseState(None, expected)
    assert result.fallback and not result.timestamp_inherited and not result.level_inherited
    assert result.text == raw
    following = parse_line("  synthetic continuation", result.state, format=format)
    assert following.state == ParseState(None, expected)
    assert not following.timestamp_inherited
    assert following.level_inherited == (expected is not None)


def test_bounded_input_rejects_oversize_and_bad_format():
    for raw, fmt in [("x" * 65537, "auto"), ("é" * 32769, "auto"), ("normal", "unknown")]:
        with pytest.raises(ValueError, match="bounded supported"):
            parse_line(raw, format=fmt)
