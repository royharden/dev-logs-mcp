"""Finite detector, conservative state and real collection-bound regressions."""

import hashlib
import hmac
from types import SimpleNamespace

import pytest

from dev_logs_mcp.shared.mcpkit.matcher import Matcher, PatternError
from dev_logs_mcp.shared.mcpkit.redact import (
    CustomRule,
    RedactionError,
    RedactionState,
    Redactor,
)


@pytest.fixture(autouse=True)
def threat_receipt(request, record_property):
    record_property("what_bug_this_catches", request.function.__doc__.strip())


@pytest.fixture
def redactor():
    return Redactor(bytes(range(32)))


def secret_cases():
    body = "A1b2" * 12
    return [
        ("Authorization: Bearer " + body, body, "BEARER"),
        ("authorization: bearer " + body, body, "BEARER"),
        ("prefix sk-" + body + " suffix", "sk-" + body, "API_KEY"),
        ("sk-proj-" + body, "sk-proj-" + body, "API_KEY"),
        ("ghp_" + body, "ghp_" + body, "API_KEY"),
        ("github_pat_" + body, "github_pat_" + body, "API_KEY"),
        ("xoxb-" + body, "xoxb-" + body, "API_KEY"),
        ("AIza" + body, "AIza" + body, "API_KEY"),
        ("AKIA" + "Z9" * 8, "AKIA" + "Z9" * 8, "AWS_KEY"),
        ("ASIA" + "Z9" * 8, "ASIA" + "Z9" * 8, "AWS_KEY"),
        ("AWS_SECRET_ACCESS_KEY=" + body, body, "SECRET"),
        ("AWS_SESSION_TOKEN=" + body, body, "SECRET"),
        ("eyJ" + body + "." + body + "." + body, "eyJ" + body + "." + body + "." + body, "JWT"),
        ("postgres://user:" + body + "@localhost/db", body, "CONNECTION_PASSWORD"),
        ("password=" + body, body, "SECRET"),
        ("DB_PASSWORD=" + body, body, "SECRET"),
        ("token: " + body, body, "SECRET"),
        ("api_key='" + body + "'", body, "SECRET"),
        ('{"nested":{"client_secret":"' + body + '"}}', body, "SECRET"),
        (r"{\"nested\":{\"token\":\"" + body + r"\"}}", body, "SECRET"),
    ]


@pytest.mark.parametrize("text,secret,type_name", secret_cases(), ids=lambda value: None)
def test_default_secret_families(redactor, text, secret, type_name):
    """Each declared finite secret family must be removed before searchable evidence exists."""
    result = redactor.redact(text)
    assert result.omitted is None
    assert secret not in result.text.value
    assert f"[{type_name}:" in result.text.value
    assert sum(count for _, count in result.counts) >= 1
    assert not Matcher(secret).search(result.text)


@pytest.mark.parametrize(
    "text",
    [
        "INFO built42 tasks",
        "passwords=public",
        "token count is12",
        "https://localhost/public",
        "AWS region=us-east",
        "JWT documentation",
        "sk-short",
    ],
)
def test_nonsecret_examples_remain_unchanged(redactor, text):
    """Finite detectors must preserve useful ordinary text and avoid keyword-only classification."""
    result = redactor.redact(text)
    assert result.text.value == text and result.counts == () and not result.omitted


def test_exact_hmac_byte_length_and_surrounding_text(redactor):
    """Byte length, keyed digest and preserved context must match an independent HMAC
    calculation.
    """
    value = "é🙂" + "x" * 4
    text = "before password=" + value + " after"
    raw = value.encode("utf-8")
    digest = hmac.new(bytes(range(32)), raw, hashlib.sha256).hexdigest()[:4]
    expected = f"before password=[SECRET:{len(raw)}:{digest}] after"
    assert redactor.redact(text).text.value == expected
    assert Redactor(b"Z" * 32).redact(text).text.value != expected


@pytest.mark.parametrize(
    "quoted",
    ['"part\\"tail"', "'part\\'tail'", '"part\\u1234tail"', '"two words"', '"unterminated tail'],
)
def test_quoted_escaped_or_unterminated_values_have_no_suffix_leak(redactor, quoted):
    """Quoted/escaped/unterminated assignments must not redact only a credential prefix."""
    text = "password=" + quoted
    result = redactor.redact(text)
    assert "part" not in result.text.value and "tail" not in result.text.value
    assert "words" not in result.text.value
    assert result.text.value.startswith("password=[SECRET:")


def test_bare_backslash_and_nested_json(redactor):
    """Backslashes in bare credentials and nested JSON cannot leave a suffix behind."""
    value = "start" + "\\middle" + "tail"
    result = redactor.redact("password=" + value)
    assert value not in result.text.value and "tail" not in result.text.value
    normal = redactor.redact('{"token":"hidden value","message":"ordinary"}')
    assert '"message":"ordinary"' in normal.text.value


def test_overlap_union_never_exposes_known_secret_suffix():
    """Crossing detectors must cover their union rather than discard the later secret suffix."""
    redactor = Redactor(bytes(32), [CustomRule("EARLY", "prefix ab"), CustomRule("LATE", "abcdef")])
    result = redactor.redact("prefix abcdef tail")
    assert result.text.value.startswith("[EARLY:13:")
    assert result.text.value.endswith(" tail")
    assert "cdef" not in result.text.value


def test_longest_then_priority_and_adjacent_spans():
    """Same-start longest precedence and stable rule priority must not clip adjacent
    replacements.
    """
    rules = [
        CustomRule("SHORT", "ab"),
        CustomRule("LONG", "abcd"),
        CustomRule("TIE", "abcd"),
        CustomRule("ADJ", "ef"),
    ]
    result = Redactor(bytes(32), rules).redact("abcdef")
    assert result.text.value.startswith("[LONG:4:") and "][ADJ:2:" in result.text.value
    assert result.counts == (("ADJ", 1), ("LONG", 1))


def test_raw_placeholder_spoofs_run_custom_and_default_rules():
    """Raw marker syntax cannot exempt embedded/contextual data from enabled detectors."""
    marker = "[TOKEN:24:abcd]"
    redactor = Redactor(bytes(32), [CustomRule("SPOOF", r"\[TOKEN:[0-9]+:[a-f0-9]{4}\]")])
    assert "[SPOOF:" in redactor.redact(marker).text.value
    assert marker not in Redactor(bytes(32)).redact("token=" + marker).text.value


def test_idempotence_requires_same_issuer_and_input_state(redactor):
    """Only actual trusted dataflow may preserve output; raw lookalikes and foreign state cannot."""
    first = redactor.redact("token=" + "X" * 24)
    again = redactor.redact(first.text)
    assert again == first and again.text is first.text
    assert redactor.redact(first.text.value).text.value != first.text.value
    with pytest.raises(RedactionError):
        Redactor(bytes(32)).redact(first.text)
    with pytest.raises(RedactionError):
        redactor.redact(first.text, RedactionState(True))


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "])
def test_pem_state_across_windows_never_retains_body(redactor, kind):
    """PEM begin/body/end and missing terminators must carry only a Boolean checkpoint state."""
    begin = redactor.redact("-----BEGIN " + kind + "PRIVATE KEY-----")
    assert begin.omitted == "private_key" and begin.state.pem_active
    body = redactor.redact("opaque" + "A" * 64, begin.state)
    assert body.omitted == "private_key" and body.state == RedactionState(True)
    assert "opaque" not in repr(body)
    restored = RedactionState(**{"pem_active": body.state.pem_active})
    end = redactor.redact("-----END " + kind + "PRIVATE KEY-----", restored)
    assert end.omitted == "private_key" and not end.state.pem_active
    assert redactor.redact("ordinary next line", end.state).text.value == "ordinary next line"


def test_pem_same_line_and_multiple_blocks(redactor):
    """Whole-line omission must dominate normal detectors and preserve the final marker state."""
    closed = redactor.redact("-----BEGIN PRIVATE KEY----- body -----END PRIVATE KEY-----")
    assert closed.omitted == "private_key" and not closed.state.pem_active
    reopened = redactor.redact("-----END PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY-----")
    assert reopened.state.pem_active
    assert "body" not in closed.text.value


@pytest.mark.parametrize("multibyte", [False, True])
def test_overlong_line_with_unseen_begin_conservatively_omits_tail(redactor, multibyte):
    """An overlong physical line may hide BEGIN; arbitrary-window continuation must stay omitted."""
    text = ("é" * 32769 if multibyte else "x" * 65537) + "-----BEGIN PRIVATE KEY-----"
    omitted = redactor.redact(text)
    assert omitted.omitted == "overlong_line" and omitted.state.pem_active
    tail = redactor.redact("unseen private body", RedactionState(omitted.state.pem_active))
    assert tail.omitted == "private_key" and "unseen" not in tail.text.value
    end = redactor.redact("-----END PRIVATE KEY-----", tail.state)
    assert not end.state.pem_active
    unread = redactor.omit_unread()
    assert unread.omitted == "overlong_line" and unread.state.pem_active


def test_pem_marker_collection_has_actual_bound(redactor):
    """Dense PEM markers cannot accumulate unbounded state operations or assume a hidden END."""
    result = redactor.redact("-----END PRIVATE KEY-----" * 257)
    assert result.omitted == "redaction_limit" and result.state.pem_active


def test_dense_detector_collection_and_output_never_prefix_clip():
    """More than256 candidate spans must whole-line omit, even if all matches overlap
    another rule.
    """
    redactor = Redactor(bytes(32), [CustomRule("SINGLE", "x")])
    assert redactor.redact("x" * 256).counts == (("SINGLE", 256),)
    overflow = redactor.redact("x" * 257)
    assert overflow.omitted == "redaction_limit" and "x" not in overflow.text.value
    expanded = redactor.redact("x" * 256 + "y" * (65536 - 256))
    assert expanded.omitted == "redaction_limit"
    assert len(expanded.text.value.encode("utf-8")) < 100


def test_candidate_iterator_stops_at_257th_pull(redactor, monkeypatch):
    """A final list cap is insufficient; actual intermediate collection must stop at first
    excess.
    """
    pulls = []

    def generate(text):
        for index in range(65536):
            pulls.append(index)
            yield SimpleNamespace(span=lambda group, index=index: (index, index + 1))

    monkeypatch.setattr(
        redactor,
        "_Redactor__rules",
        (SimpleNamespace(regex=SimpleNamespace(finditer=generate), group=0, type_name="DENSE"),),
    )
    result = redactor.redact("x" * 65536)
    assert result.omitted == "redaction_limit" and pulls == list(range(257))


@pytest.mark.parametrize("pattern", ["", "a*", "^", "$", r"\b"])
def test_zero_width_custom_detectors_safely_omit(pattern):
    """A zero-width detector cannot produce a dense expanding output or accidentally leak
    raw text.
    """
    redactor = Redactor(bytes(32), [CustomRule("ZERO", pattern)])
    assert redactor.redact("ordinary").omitted == "redaction_limit"


def test_custom_rules_always_run_without_trigger_assumptions():
    """A custom detector with no built-in keyword must still inspect every bounded raw line."""
    redactor = Redactor(bytes(32), [CustomRule("CUSTOM", "ordinary[0-9]+")])
    result = redactor.redact("prefix ordinary42 suffix")
    assert "ordinary42" not in result.text.value and "[CUSTOM:" in result.text.value
    assert result.text.value.startswith("prefix ") and result.text.value.endswith(" suffix")


def test_custom_limits_duplicate_types_and_defaults_cannot_be_disabled():
    """Malformed or excess rules must reject while empty custom configuration keeps
    defaults enabled.
    """
    rules = [CustomRule("C" + str(i), "nomatch" + str(i)) for i in range(32)]
    assert Redactor(bytes(32), rules).redact("ordinary").text.value == "ordinary"
    for invalid in (
        rules + [CustomRule("MORE", "x")],
        [CustomRule("SECRET", "x")],
        [CustomRule("LOW", "x"), CustomRule("LOW", "y")],
        [CustomRule("bad", "x")],
        [CustomRule("X" * 33, "x")],
        [None],
        "disable",
    ):
        with pytest.raises(RedactionError):
            Redactor(bytes(32), invalid)
    value = "Y" * 24
    assert value not in Redactor(bytes(32), ()).redact("token=" + value).text.value


def test_custom_pattern_and_key_errors_are_sanitized(capfd):
    """Invalid injected key/pattern must never be printed through configuration exceptions
    or repr.
    """
    for invalid in (b"short", "Z" * 32, bytearray(32)):
        with pytest.raises(RedactionError):
            Redactor(invalid)
    for pattern in ("x" * 513, "é" * 257, "(?=private_sentinel)"):
        with pytest.raises(PatternError) as error:
            Redactor(bytes(32), [CustomRule("INVALID", pattern)])
        assert "private_sentinel" not in str(error.value)
    assert capfd.readouterr() == ("", "")
    assert "private_sentinel" not in repr(CustomRule("TYPE", "private_sentinel"))


@pytest.mark.parametrize("value", [None, True, b"text", "\ud800"])
def test_bad_text_and_state_inputs_refuse_without_echo(redactor, value):
    """Invalid Unicode/types and ambiguous checkpoint state must fail before redaction work."""
    with pytest.raises(RedactionError):
        redactor.redact(value)
    with pytest.raises(RedactionError):
        redactor.redact("ordinary", state=True)
    with pytest.raises(RedactionError):
        RedactionState(1)


def test_process_keys_generated_privately_not_shared(monkeypatch):
    """Unspecified keys must be process-random32bytes and never appear in
    repr/results/checkpoints.
    """
    from dev_logs_mcp.shared.mcpkit import redact

    calls = []

    def random_key(size):
        calls.append(size)
        return bytes([len(calls)]) * size

    monkeypatch.setattr(redact.secrets, "token_bytes", random_key)
    one, two = Redactor(), Redactor()
    value = "token=" + "A" * 24
    assert calls == [32, 32]
    assert one.redact(value).text.value != two.redact(value).text.value
    assert "\\x01" not in repr(one) + repr(one.redact(value))


@pytest.mark.parametrize("kind", ["api", "jwt"])
def test_base64url_or_key_nonword_suffix_is_not_exposed(redactor, kind):
    """A regex word-boundary must not backtrack and expose valid trailing key/signature bytes."""
    body = "A1b2" * 8
    value = ("sk-" + body if kind == "api" else "eyJ" + body + "." + body + "." + body) + "---"
    result = redactor.redact("prefix " + value + " suffix")
    assert value not in result.text.value and "---" not in result.text.value
    assert result.text.value.endswith(" suffix")


@pytest.mark.parametrize(
    "name", ["\ud800", "É", "X" * 65536], ids=["surrogate", "non-ascii", "huge"]
)
def test_malformed_type_names_reject_before_re2(name, capfd):
    """Invalid Unicode or huge labels must not reach an encoder/regex or escape sanitized errors."""
    with pytest.raises(RedactionError):
        Redactor(bytes(32), [CustomRule(name, "ordinary")])
    assert capfd.readouterr() == ("", "")


def test_redaction_bypass_negative_control_is_detected(monkeypatch):
    """The secret-oracle assertion must actually fail when enabled detectors are sabotaged."""
    value = "synthetic" + "Z" * 24

    def assert_protected(redactor):
        result = redactor.redact("token=" + value)
        assert value not in result.text.value, "raw secret leak detected"
        assert not Matcher(value).search(result.text), "raw query oracle detected"

    intact, sabotaged = Redactor(bytes(32)), Redactor(bytes(32))
    assert_protected(intact)
    monkeypatch.setattr(sabotaged, "_Redactor__rules", ())
    with pytest.raises(AssertionError, match="raw secret leak detected"):
        assert_protected(sabotaged)
