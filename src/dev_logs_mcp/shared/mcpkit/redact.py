"""Finite-pattern secret redaction with bounded spans, output and PEM state.

Placeholders disclose category, matched UTF8 length and process-local equality;
four hex HMAC digits can collide and provide no security/equality proof. Detection
does not recognize every possible secret. No raw values or keys persist in state.
"""

import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field

from .errors import MAX_CUSTOM_RULES, MAX_PHYSICAL_LINE_BYTES
from .matcher import RedactedText, _bounded_text, _compile, _make_redacted

MAX_REDACTION_SPANS = 256
MAX_REDACTED_BYTES = MAX_PHYSICAL_LINE_BYTES


class RedactionError(ValueError):
    code = "INVALID_ARGUMENT"

    def __init__(self) -> None:
        super().__init__("Redaction input or configuration violates the bounded policy")


@dataclass(frozen=True, slots=True)
class RedactionState:
    pem_active: bool = False

    def __post_init__(self) -> None:
        if type(self.pem_active) is not bool:
            raise RedactionError()


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: RedactedText
    state: RedactionState
    counts: tuple[tuple[str, int], ...] = ()

    @property
    def omitted(self) -> str | None:
        return self.text.omitted


@dataclass(frozen=True, slots=True, repr=False)
class CustomRule:
    type_name: str
    pattern: str = field(repr=False)

    def __repr__(self) -> str:
        return "CustomRule(<configured detector>)"


@dataclass(frozen=True, slots=True, repr=False)
class _Rule:
    type_name: str
    regex: object
    group: int = 0


@dataclass(frozen=True, slots=True)
class _Span:
    start: int
    end: int
    priority: int
    type_name: str


# Quoted JSON/assignment values include escaped characters and their closing quote.
# Escaped outer JSON and unterminated quoted values conservatively redact the suffix.
_VALUE = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\\["'][^\r\n]*|["'][^\r\n]*|[^\s"',;}&]+)"""
_DEFAULTS = (
    ("BEARER", r"\bBearer\s+(?P<value>[A-Za-z0-9._~+/-]+=*)", "value", False),
    (
        "API_KEY",
        r"\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{12,}|"
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{20,})",
        0,
        True,
    ),
    ("AWS_KEY", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0, True),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}", 0, True),
    (
        "CONNECTION_PASSWORD",
        r"\b[A-Za-z][A-Za-z0-9+.-]{1,31}://[^/\s:@]+:(?P<value>[^@\s/]+)@",
        "value",
        True,
    ),
    (
        "SECRET",
        r"""\b(?:[A-Za-z0-9_]{1,32}[_-])?(?:password|passwd|pwd|secret|token|api[_-]?key|"""
        r"""access[_-]?token|client[_-]?secret|aws_secret_access_key|aws_session_token)"""
        r"""\b["'\\]*\s*[:=]\s*(?P<value>""" + _VALUE + ")",
        "value",
        False,
    ),
)


class Redactor:
    def __init__(self, key: bytes | None = None, custom_rules: Sequence[CustomRule] = ()) -> None:
        if key is not None and (type(key) is not bytes or len(key) != 32):
            raise RedactionError()
        if (
            not isinstance(custom_rules, Sequence)
            or isinstance(custom_rules, str | bytes)
            or len(custom_rules) > MAX_CUSTOM_RULES
        ):
            raise RedactionError()
        self.__key = secrets.token_bytes(32) if key is None else key
        self.__issuer = object()
        self.__pem = _compile(r"-----(BEGIN|END) (?:[A-Z0-9]+ )*PRIVATE KEY-----")
        rules = []
        for name, pattern, group, case in _DEFAULTS:
            regex = _compile(pattern, case)
            # google-re2 span() requires an integer even though group() accepts names.
            group_index = regex.groupindex[group] if isinstance(group, str) else group
            rules.append(_Rule(name, regex, group_index))
        type_check = _compile(r"[A-Z][A-Z0-9_]{0,31}")
        names = {rule.type_name for rule in rules} | {"PRIVATE_KEY", "OMITTED"}
        for rule in custom_rules:
            if (
                not isinstance(rule, CustomRule)
                or type(rule.type_name) is not str
                or not 1 <= len(rule.type_name) <= 32
                or not rule.type_name.isascii()
                or not type_check.fullmatch(rule.type_name)
                or rule.type_name in names
            ):
                raise RedactionError()
            names.add(rule.type_name)
            rules.append(_Rule(rule.type_name, _compile(rule.pattern)))
        self.__rules = tuple(rules)

    def __repr__(self) -> str:
        return "Redactor(<bounded enabled detectors>)"

    def _result(
        self,
        value: str,
        state: RedactionState,
        before: RedactionState,
        counts: tuple[tuple[str, int], ...] = (),
        omitted: str | None = None,
    ) -> RedactionResult:
        proof = (self.__issuer, before, state, counts)
        return RedactionResult(_make_redacted(value, omitted, proof), state, counts)

    def _omit(self, reason: str, state: RedactionState, before: RedactionState) -> RedactionResult:
        return self._result(f"[OMITTED:{reason.upper()}]", state, before, omitted=reason)

    def omit_unread(self, state: RedactionState | None = None) -> RedactionResult:
        """An unread/oversized line could enter PEM; carry uncertainty until a real END."""
        before = self._state(state)
        return self._omit("overlong_line", RedactionState(True), before)

    @staticmethod
    def _state(state: RedactionState | None) -> RedactionState:
        if state is not None and not isinstance(state, RedactionState):
            raise RedactionError()
        return RedactionState() if state is None else state

    def redact(
        self, text: str | RedactedText, state: RedactionState | None = None
    ) -> RedactionResult:
        before = self._state(state)
        if isinstance(text, RedactedText):
            proof = text._proof
            if (
                not isinstance(proof, tuple)
                or len(proof) != 4
                or proof[0] is not self.__issuer
                or proof[1] != before
            ):
                raise RedactionError()
            return RedactionResult(text, proof[2], proof[3])
        if type(text) is not str:
            raise RedactionError()
        try:
            _bounded_text(text)
        except ValueError:
            # Invalid Unicode is refused; unread long input is a conservative omission.
            if len(text) > MAX_PHYSICAL_LINE_BYTES:
                return self.omit_unread(before)
            try:
                encoded_size = len(text.encode("utf-8"))
            except UnicodeError:
                raise RedactionError() from None
            if encoded_size > MAX_PHYSICAL_LINE_BYTES:
                return self.omit_unread(before)
            raise RedactionError() from None

        pem_active, pem_seen = before.pem_active, before.pem_active
        for index, marker in enumerate(self.__pem.finditer(text)):
            if index == MAX_REDACTION_SPANS:
                return self._omit("redaction_limit", RedactionState(True), before)
            pem_seen = True
            pem_active = marker.group(1) == "BEGIN"
        after = RedactionState(pem_active)
        if pem_seen:
            return self._omit("private_key", after, before)

        spans: list[_Span] = []
        for priority, rule in enumerate(self.__rules):
            for match in rule.regex.finditer(text):
                start, end = match.span(rule.group)
                if start == end or len(spans) == MAX_REDACTION_SPANS:
                    return self._omit("redaction_limit", after, before)
                spans.append(_Span(start, end, priority, rule.type_name))
        spans.sort(key=lambda span: (span.start, -span.end, span.priority))
        selected: list[_Span] = []
        end = 0
        for span in spans:
            if span.start >= end:
                selected.append(span)
                end = span.end
            elif span.end > end:
                # Union crossing overlaps: discarding one detector would expose its suffix.
                previous = selected[-1]
                selected[-1] = _Span(
                    previous.start, span.end, previous.priority, previous.type_name
                )
                end = span.end

        parts: list[str] = []
        counts: dict[str, int] = {}
        offset = output_bytes = 0
        for span in selected:
            raw = text[span.start : span.end].encode("utf-8")
            digest = hmac.new(self.__key, raw, hashlib.sha256).hexdigest()[:4]
            marker = f"[{span.type_name}:{len(raw)}:{digest}]"
            literal = text[offset : span.start]
            output_bytes += len(literal.encode("utf-8")) + len(marker)
            if output_bytes > MAX_REDACTED_BYTES:
                return self._omit("redaction_limit", after, before)
            parts.extend((literal, marker))
            counts[span.type_name] = counts.get(span.type_name, 0) + 1
            offset = span.end
        suffix = text[offset:]
        if output_bytes + len(suffix.encode("utf-8")) > MAX_REDACTED_BYTES:
            return self._omit("redaction_limit", after, before)
        parts.append(suffix)
        return self._result("".join(parts), after, before, tuple(sorted(counts.items())))
