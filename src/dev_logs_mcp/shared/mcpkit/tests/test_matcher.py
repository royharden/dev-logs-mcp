"""Bounded query tests over the actual RE2 engine and redacted dataflow."""

import dataclasses
from types import SimpleNamespace

import pytest

from dev_logs_mcp.shared.mcpkit.matcher import Matcher, PatternError, RedactedText
from dev_logs_mcp.shared.mcpkit.redact import Redactor


@pytest.fixture(autouse=True)
def threat_receipt(request, record_property):
    record_property("what_bug_this_catches", request.function.__doc__.strip())


@pytest.fixture
def redactor():
    return Redactor(bytes(range(32)))


@pytest.mark.parametrize("pattern", [r"(?=sentinel)", r"(sentinel)\1", "[", "\ud800", True])
def test_bad_pattern_is_sanitized_including_native_stderr(pattern, capfd):
    """Unsupported syntax, Unicode and types must not echo patterns through RE2 stderr/errors."""
    with pytest.raises(PatternError) as error:
        Matcher(pattern)
    assert error.value.code == "INVALID_PATTERN"
    assert "sentinel" not in str(error.value)
    assert error.value.__suppress_context__
    assert capfd.readouterr() == ("", "")


def test_pattern_bytes_boundary_and_strict_options(redactor):
    """UTF8 bytes rather than characters must enforce512 and reject ambiguous case settings."""
    assert Matcher("é" * 256).search(redactor.redact("é" * 256).text)
    with pytest.raises(PatternError):
        Matcher("é" * 256 + "x")
    with pytest.raises(PatternError):
        Matcher("x", case_sensitive=1)


def test_query_can_only_receive_redactor_value(redactor, monkeypatch):
    """A raw string must be rejected before the query engine can inspect it."""
    query = Matcher("x")
    calls = []
    monkeypatch.setattr(
        query, "_Matcher__regex", SimpleNamespace(search=lambda text: calls.append(text))
    )
    with pytest.raises(TypeError):
        query.search("raw sentinel")
    assert calls == []
    with pytest.raises(TypeError):
        RedactedText("raw sentinel")
    value = redactor.redact("ordinary").text
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.value = "raw sentinel"


def test_secret_match_oracle_never_sees_raw_value(redactor, monkeypatch):
    """Both Boolean and positions queries must see only the redacted text, including custom
    rules.
    """
    secret = "value" + "Z" * 24
    value = redactor.redact("token=" + secret).text
    assert not Matcher(secret).search(value)
    assert Matcher(secret).find_matches(value).matches == ()
    assert Matcher("SECRET").search(value)
    query = Matcher("ordinary")
    observed = []
    monkeypatch.setattr(
        query, "_Matcher__regex", SimpleNamespace(search=lambda text: observed.append(text))
    )
    assert not query.search(value)
    assert observed == [value.value] and secret not in observed[0]


def test_unicode_positions_and_case_are_explicit(redactor):
    """Query character indices must not be mistaken for raw UTF8 byte offsets or implicit casing."""
    value = redactor.redact("é🙂 AbC é").text
    page = Matcher("é").find_matches(value)
    assert [(match.start, match.end) for match in page.matches] == [(0, 1), (7, 8)]
    assert page.complete
    assert not Matcher("abc").search(value)
    assert Matcher("abc", case_sensitive=False).search(value)


def test_zero_width_queries_progress_and_stop_at_real_cap(redactor):
    """Empty-match queries must make progress and return bounded complete/truncated status."""
    page = Matcher("").find_matches(redactor.redact("é🙂x").text)
    assert [(m.start, m.end) for m in page.matches] == [(i, i) for i in range(4)]
    assert page.complete
    capped = Matcher("").find_matches(redactor.redact("x" * 65536).text)
    assert len(capped.matches) == 100 and not capped.complete


@pytest.mark.parametrize("limit", [True, 0, -1, 101, 1.0, None])
def test_query_limit_cannot_raise_bound(redactor, limit):
    """Invalid per-call limits must not bypass the fixed100-match collection ceiling."""
    with pytest.raises(ValueError):
        Matcher("x").find_matches(redactor.redact("x").text, limit=limit)


def test_dense_iterator_only_pulls_one_beyond_page(redactor, monkeypatch):
    """The implementation must stream instead of materializing all matches before taking100."""
    query = Matcher("x")
    pulls = []

    def generate(text):
        for index in range(65536):
            pulls.append(index)
            yield SimpleNamespace(span=lambda index=index: (index, index + 1))

    monkeypatch.setattr(query, "_Matcher__regex", SimpleNamespace(finditer=generate))
    page = query.find_matches(redactor.redact("x" * 65536).text)
    assert len(page.matches) == 100 and pulls == list(range(101))


def test_broken_iterator_progress_guard(redactor, monkeypatch):
    """A nonprogressing iterator must fail rather than return repeated empty coordinates."""
    query = Matcher("")
    match = SimpleNamespace(span=lambda: (0, 0))
    monkeypatch.setattr(
        query, "_Matcher__regex", SimpleNamespace(finditer=lambda text: iter([match, match]))
    )
    with pytest.raises(ValueError, match="progress"):
        query.find_matches(redactor.redact("x").text)


def test_omitted_bodies_are_never_searchable(redactor, monkeypatch):
    """An omission marker must not pretend to be searchable evidence from an excluded raw body."""
    omitted = redactor.omit_unread().text
    query = Matcher("OMITTED")
    monkeypatch.setattr(query, "_Matcher__regex", SimpleNamespace())
    assert not query.search(omitted)
    page = query.find_matches(omitted)
    assert page.omitted == "overlong_line" and page.matches == ()


def test_representations_never_include_query_or_body(redactor):
    """Repr/debug surfaces must not leak even query values or finite-detector misses."""
    marker = "untrusted" + "sentinel"
    assert marker not in repr(Matcher(marker))
    assert marker not in repr(redactor.redact(marker).text)
