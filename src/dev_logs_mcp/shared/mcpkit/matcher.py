"""RE2-only queries over bounded, explicitly redacted line values.

The wrapper records trusted Python dataflow, not an authentication or sandbox claim.
Query coordinates are Unicode character indices in redacted text, not source bytes.
"""

from dataclasses import dataclass, field

import re2

from .errors import MAX_PATTERN_BYTES, MAX_PHYSICAL_LINE_BYTES

MAX_QUERY_MATCHES = 100
RE2_MEMORY_BYTES = 1024 * 1024


class PatternError(ValueError):
    code = "INVALID_PATTERN"

    def __init__(self) -> None:
        super().__init__("Pattern violates the bounded RE2 policy")


def _bounded_text(value: object) -> str:
    if type(value) is not str or len(value) > MAX_PHYSICAL_LINE_BYTES:
        raise ValueError("bounded UTF8 text required")
    try:
        if len(value.encode("utf-8")) > MAX_PHYSICAL_LINE_BYTES:
            raise ValueError("bounded UTF8 text required")
    except UnicodeError:
        raise ValueError("bounded UTF8 text required") from None
    return value


def _compile(pattern: str, case_sensitive: bool = True):
    try:
        if (
            type(pattern) is not str
            or len(pattern) > MAX_PATTERN_BYTES
            or len(pattern.encode("utf-8")) > MAX_PATTERN_BYTES
            or type(case_sensitive) is not bool
        ):
            raise PatternError()
        options = re2.Options()
        options.log_errors = False
        options.case_sensitive = case_sensitive
        options.max_mem = RE2_MEMORY_BYTES
        return re2.compile(pattern, options=options)
    except Exception:
        raise PatternError() from None


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RedactedText:
    value: str
    omitted: str | None
    _proof: object = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("Redactor-produced text required")

    def __repr__(self) -> str:
        return f"RedactedText(omitted={self.omitted!r})"


def _make_redacted(value: str, omitted: str | None, proof: object) -> RedactedText:
    _bounded_text(value)
    result = object.__new__(RedactedText)
    object.__setattr__(result, "value", value)
    object.__setattr__(result, "omitted", omitted)
    object.__setattr__(result, "_proof", proof)
    return result


@dataclass(frozen=True, slots=True)
class TextMatch:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class MatchPage:
    matches: tuple[TextMatch, ...]
    complete: bool
    omitted: str | None = None


class Matcher:
    def __init__(self, pattern: str, case_sensitive: bool = True) -> None:
        self.__regex = _compile(pattern, case_sensitive)

    def __repr__(self) -> str:
        return "Matcher(<bounded RE2 pattern>)"

    @staticmethod
    def _input(text: RedactedText) -> str:
        if not isinstance(text, RedactedText):
            raise TypeError("Redactor-produced text required")
        return _bounded_text(text.value)

    def search(self, text: RedactedText) -> bool:
        value = self._input(text)
        return False if text.omitted else self.__regex.search(value) is not None

    def find_matches(self, text: RedactedText, limit: int = MAX_QUERY_MATCHES) -> MatchPage:
        if type(limit) is not int or not 1 <= limit <= MAX_QUERY_MATCHES:
            raise ValueError("invalid query match ceiling")
        value = self._input(text)
        if text.omitted:
            return MatchPage((), True, text.omitted)
        matches: list[TextMatch] = []
        previous: tuple[int, int] | None = None
        for match in self.__regex.finditer(value):
            span = match.span()
            # RE2 advances empty matches; also guard a broken/injected iterator.
            if previous is not None and (span == previous or span[0] < previous[0]):
                raise ValueError("query matcher failed to make progress")
            if len(matches) == limit:
                return MatchPage(tuple(matches), False)
            matches.append(TextMatch(*span))
            previous = span
        return MatchPage(tuple(matches), True)
