"""Fixed public-input tool methods; no Gold, files, providers or source acquisition.

The trusted controller supplies a transport, actual implementation digest and
frozen-source bindings. Toy transports do not become native execution evidence.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic

from ..contracts import validate_request
from ..index import MAX_INDEX_LINES
from ..shared.evalkit.identity import canonical_bytes
from ..shared.evalkit.models import Prediction, PublicMethodInput, SourceRef
from ..shared.mcpkit.conformance.cases import Observation
from ..shared.mcpkit.models import ToolEnvelope
from .domain import METHODS, EvidenceStore, PublicSymptom

VERSION = "s1_fixed_methods_v1"
_STOPWORDS = frozenset({"the", "and", "with", "from", "this", "that", "when", "while"})


def symptom_pattern(hint: str) -> str:
    """A fixed, bounded literal-token OR; no case IDs or private target lookup."""
    words = re.findall(r"[\w.:-]{3,32}", hint)
    selected = []
    for word in words:
        if word.casefold() in _STOPWORDS or word.casefold() in selected:
            continue
        candidate = selected + [word.casefold()]
        pattern = "(?i)(?:" + "|".join(re.escape(value) for value in candidate) + ")"
        if len(pattern.encode("utf-8")) > 512:
            break
        selected = candidate
        if len(selected) == 6:
            break
    if selected:
        return "(?i)(?:" + "|".join(re.escape(value) for value in selected) + ")"
    escaped = ""
    for character in hint:
        candidate = escaped + re.escape(character)
        if len(candidate.encode("utf-8")) > 500:
            break
        escaped = candidate
    if not escaped:
        raise ValueError("empty_symptom_pattern")
    return "(?i)" + escaped


@dataclass(frozen=True)
class CallMetrics:
    attempted_calls: int
    returned_calls: int
    observed_frame_bytes: int
    measured_read_bytes: int | None
    elapsed_seconds: float
    frame_origins: tuple[str, ...]


@dataclass(frozen=True)
class ToolReply:
    evidence_ref: str
    envelope: ToolEnvelope = field(repr=False)
    source_ref: SourceRef | None = None


class MethodCallError(ValueError):
    def __init__(self, status: str, code: str):
        super().__init__(code)
        self.status, self.code = status, code


class RecordingClient:
    """One public case/method binding and cooperative deadline; not a hard scheduler."""

    def __init__(
        self,
        item_id: str,
        method: str,
        source_id: str,
        transport: Callable[[str, dict], Observation],
        evidence: EvidenceStore,
        *,
        max_calls=64,
        max_seconds=30.0,
        clock=monotonic,
    ):
        PublicSymptom(source_id=source_id, symptom_hint="case_binding")
        if (
            method not in METHODS
            or not item_id
            or len(item_id) > 512
            or type(max_calls) is not int
            or not 1 <= max_calls <= 128
            or type(max_seconds) not in (int, float)
            or not 0 < max_seconds <= 60
        ):
            raise ValueError("invalid_recording_client_bounds")
        self.item_id, self.method, self.source_id = item_id, method, source_id
        self._transport, self._evidence = transport, evidence
        self._clock, self._started = clock, clock()
        self._max_calls, self._max_seconds = max_calls, max_seconds
        self._attempts = self._returned = self._frame_bytes = self._reads = 0
        self._unmeasured = False
        self._origins = set()
        self._generation = None

    def metrics(self) -> CallMetrics:
        return CallMetrics(
            self._attempts,
            self._returned,
            self._frame_bytes,
            None if self._unmeasured else self._reads,
            max(0.0, self._clock() - self._started),
            tuple(sorted(self._origins)),
        )

    def call(self, tool: str, arguments: dict) -> ToolReply:
        if self._attempts >= self._max_calls or self._clock() - self._started >= self._max_seconds:
            raise MethodCallError("blocked", "method_budget_exhausted")
        try:
            validate_request(tool, arguments)
        except ValueError:
            raise MethodCallError("invalid", "invalid_tool_arguments") from None
        if tool != "list_sources" and arguments.get("source_id") != self.source_id:
            raise MethodCallError("blocked", "cross_source_request")
        self._attempts += 1
        started = self._clock()
        try:
            observation = self._transport(tool, arguments)
        except Exception:
            self._unmeasured = True
            raise MethodCallError("unavailable", "transport_unavailable") from None
        self._returned += 1
        if not isinstance(observation, Observation):
            self._unmeasured = True
            raise MethodCallError("invalid", "invalid_tool_observation")
        self._frame_bytes += len(observation.frame)
        self._origins.add(observation.frame_origin)
        if observation.measured_read_bytes is None:
            self._unmeasured = True
        else:
            self._reads += observation.measured_read_bytes
        if self._clock() - started > 5 or self._clock() - self._started >= self._max_seconds:
            raise MethodCallError("blocked", "method_deadline_exceeded")
        try:
            reference = self._evidence.record(self.item_id, self.method, tool, observation)
            value = json.loads(observation.frame)["result"]["structuredContent"]
            envelope = ToolEnvelope.model_validate_json(canonical_bytes(value))
            if envelope.source_id is not None and envelope.source_id != self.source_id:
                raise ValueError
            if envelope.generation_id is not None:
                if self._generation is not None and self._generation != envelope.generation_id:
                    raise MethodCallError("stale", "generation_changed")
                self._generation = envelope.generation_id
            source_ref = self._evidence._sources.get(envelope.source_id)
        except MethodCallError:
            raise
        except Exception:
            raise MethodCallError("invalid", "invalid_tool_reply") from None
        if not envelope.ok:
            raise MethodCallError("unavailable", "tool_operation_failed")
        return ToolReply(reference, envelope, source_ref)


ClientFactory = Callable[[str, str, str], RecordingClient]


class FixedMethod:
    """The same public hint/source goes to each named method, never a Gold record."""

    def __init__(
        self,
        method: str,
        client_factory: ClientFactory,
        implementation_sha256: str,
        *,
        max_calls=64,
        max_seconds=30.0,
    ):
        if (
            method not in METHODS
            or not re.fullmatch(r"[0-9a-f]{64}", implementation_sha256)
            or type(max_calls) is not int
            or not 1 <= max_calls <= 64
            or type(max_seconds) not in (int, float)
            or not 0 < max_seconds <= 60
        ):
            raise ValueError("fixed_method_identity_invalid")
        self.method, self._factory = method, client_factory
        self._max_calls, self._max_seconds = max_calls, max_seconds
        self.config_sha256 = hashlib.sha256(
            canonical_bytes(
                {
                    "version": VERSION,
                    "method": method,
                    "implementation_sha256": implementation_sha256,
                    "pattern": "six_literal_tokens_or",
                    "page_lines": 100,
                    "range_context": [5, 20],
                    "source_policy": "public_alias_only",
                    "max_calls": max_calls,
                    "max_seconds": max_seconds,
                }
            )
        ).hexdigest()
        self.metrics_by_item: dict[str, CallMetrics] = {}
        self._attempted = set()

    @staticmethod
    def _range(client, source, anchor):
        anchor = min(MAX_INDEX_LINES, anchor)
        return client.call(
            "read_range",
            {
                "source_id": source,
                "start_line": max(1, anchor - 5),
                "end_line": min(MAX_INDEX_LINES, anchor + 20),
            },
        )

    def _scripted(self, client, public):
        listed = client.call("list_sources", {})
        entries = [s for s in listed.envelope.sources if s.id == public.source_id]
        if not entries or not entries[0].readable:
            raise MethodCallError("unavailable", "source_unavailable")
        errors = client.call("errors", {"source_id": public.source_id})
        search = client.call(
            "search",
            {
                "source_id": public.source_id,
                "pattern": symptom_pattern(public.symptom_hint),
                "max_matches": 100,
                "context": 2,
            },
        )
        anchor = (
            search.envelope.matches[0].line_no
            if search.envelope.matches
            else errors.envelope.groups[0].first_in_coverage.line_no
            if errors.envelope.groups
            else None
        )
        last = (
            self._range(client, public.source_id, anchor)
            if anchor is not None
            else client.call("tail", {"source_id": public.source_id, "lines": 100})
        )
        return [errors, search, last]

    def _grep(self, client, public):
        replies, cursor, seen = [], None, set()
        while True:
            arguments = {
                "source_id": public.source_id,
                "pattern": symptom_pattern(public.symptom_hint),
                "max_matches": 100,
                "context": 2,
                "direction": "oldest_first",
            }
            if cursor is not None:
                arguments["cursor"] = cursor
            reply = client.call("search", arguments)
            replies.append(reply)
            cursor = reply.envelope.next_cursor
            if cursor is None:
                break
            if cursor in seen:
                raise MethodCallError("blocked", "pagination_no_progress")
            seen.add(cursor)
        first = next((m.line_no for reply in replies for m in reply.envelope.matches), None)
        if first is not None:
            replies.append(self._range(client, public.source_id, first))
        return replies

    def _naive(self, client, public):
        replies, start = [], 1
        while start <= MAX_INDEX_LINES:
            reply = client.call(
                "read_range",
                {
                    "source_id": public.source_id,
                    "start_line": start,
                    "end_line": min(MAX_INDEX_LINES, start + 99),
                },
            )
            replies.append(reply)
            if not reply.envelope.lines:
                break
            next_line = max(row.line_no for row in reply.envelope.lines) + 1
            if next_line <= start:
                raise MethodCallError("blocked", "pagination_no_progress")
            total = reply.envelope.coverage.total_lines
            if total is not None and next_line > total:
                break
            start = next_line
        return replies

    def predict(self, public_input: PublicMethodInput) -> Prediction:
        public = PublicSymptom.model_validate(public_input.public_payload)
        if public_input.item_id in self._attempted:
            raise ValueError("case_already_attempted")
        self._attempted.add(public_input.item_id)
        client = self._factory(public_input.item_id, self.method, public.source_id)
        if (client.item_id, client.method, client.source_id) != (
            public_input.item_id,
            self.method,
            public.source_id,
        ):
            raise ValueError("client_binding_mismatch")
        if (client._max_calls, client._max_seconds) != (self._max_calls, self._max_seconds):
            raise ValueError("client_budget_binding_mismatch")
        status, issues, replies = "ok", [], []
        try:
            replies = {
                "s1_scripted": self._scripted,
                "redacted_grep_range": self._grep,
                "naive_paged_range": self._naive,
            }[self.method](client, public)
        except MethodCallError as error:
            status, issues = error.status, [error.code]
        finally:
            self.metrics_by_item[public_input.item_id] = client.metrics()
        evidence = [reply for reply in replies if reply.envelope.lines or reply.envelope.groups]
        if status == "ok" and not evidence:
            status, issues = "abstained", ["no_observed_evidence"]
        refs = list(dict.fromkeys(reply.source_ref for reply in evidence if reply.source_ref))
        return Prediction.model_validate_json(
            canonical_bytes(
                {
                    "item_id": public_input.item_id,
                    "method": self.method,
                    "method_version": VERSION,
                    "config_sha256": self.config_sha256,
                    "model": None,
                    "origin": "synthetic",
                    "status": status,
                    "domain_payload": {"evidence_refs": [r.evidence_ref for r in evidence]}
                    if status == "ok"
                    else None,
                    "machine_output": None,
                    "human_effective_output": None,
                    "human_provenance_ref": None,
                    "issues": issues,
                    "ledger_refs": [],
                    "source_refs": [r.model_dump(mode="json") for r in refs]
                    if status == "ok"
                    else [],
                }
            )
        )
