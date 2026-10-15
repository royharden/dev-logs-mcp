"""Original toy transports, not the independent corpus or native tool execution."""

import pytest

from dev_logs_mcp.evaluation.domain import METHODS, EvidenceStore, IncidentAdapter
from dev_logs_mcp.evaluation.methods import (
    FixedMethod,
    MethodCallError,
    RecordingClient,
    symptom_pattern,
)
from dev_logs_mcp.shared.evalkit.identity import canonical_bytes
from dev_logs_mcp.shared.evalkit.models import GoldRecord, PublicMethodInput, SourceRef
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.conformance.cases import Observation
from dev_logs_mcp.shared.mcpkit.matcher import Matcher
from dev_logs_mcp.shared.mcpkit.models import (
    Coverage,
    ErrorGroup,
    LogLine,
    Match,
    SourceInfo,
    ToolEnvelope,
    Truncation,
)

SOURCE = SourceRef(handle="toy_handle", sha256="a" * 64)
PUBLIC = PublicMethodInput.model_validate_json(
    canonical_bytes(
        {
            "item_id": "toy_case",
            "input_sha256": "b" * 64,
            "public_config_refs": [],
            "public_payload": {"source_id": "toy", "symptom_hint": "Toy operation failed"},
        }
    )
)


class ToyTransport:
    def __init__(self, *, measured=17):
        self.calls = []
        self.measured = measured
        self.total = 140
        self.generation = "toy_generation"

    def envelope(self, tool, arguments):
        row = LogLine(line_no=110, byte_offset=400, text="toy operation failed toy_trace")
        if tool == "list_sources":
            return ToolEnvelope(
                ok=True,
                sources=[
                    SourceInfo(
                        id="toy",
                        display_path="toy.log",
                        size=1000,
                        readable=True,
                    )
                ],
            )
        base = {"ok": True, "source_id": "toy", "generation_id": self.generation}
        if tool == "errors":
            return ToolEnvelope(
                **base,
                groups=[
                    ErrorGroup(
                        signature="toy failure",
                        level="ERROR",
                        first_in_coverage=row,
                        occurrence_count_in_coverage=1,
                        trace=[row],
                    )
                ],
            )
        if tool == "search":
            return ToolEnvelope(**base, lines=[row], matches=[Match(line_no=110)])
        if tool == "tail":
            return ToolEnvelope(**base, lines=[row])
        start, end = arguments["start_line"], arguments["end_line"]
        lines = [
            LogLine(
                line_no=n,
                byte_offset=n * 3,
                text="toy operation failed toy_trace" if n == 110 else "toy line",
            )
            for n in range(start, min(self.total, end) + 1)
        ]
        return ToolEnvelope(
            **base,
            lines=lines,
            coverage=Coverage(
                total_lines=self.total,
                first_line=start if lines else None,
                last_line=lines[-1].line_no if lines else None,
            ),
        )

    def __call__(self, tool, arguments):
        self.calls.append((tool, dict(arguments)))
        envelope = self.envelope(tool, arguments)
        request_id = len(self.calls)
        return Observation(
            frame=OutputBudget().render(envelope, request_id).wire_bytes,
            frame_origin="adapter_serialization",
            measured_read_bytes=self.measured,
            request_id=request_id,
        )


def make_method(name, transport, *, max_calls=64, max_seconds=30.0, clock=None, code="e" * 64):
    store = EvidenceStore({"toy": SOURCE})

    def factory(item_id, method, source):
        extra = {} if clock is None else {"clock": clock}
        return RecordingClient(
            item_id,
            method,
            source,
            transport,
            store,
            max_calls=max_calls,
            max_seconds=max_seconds,
            **extra,
        )

    return FixedMethod(name, factory, code, max_calls=max_calls, max_seconds=max_seconds)


@pytest.mark.parametrize("name", METHODS)
def test_all_methods_receive_same_public_hint_and_alias_only(name):
    transport = ToyTransport()
    method = make_method(name, transport)
    result = method.predict(PUBLIC)
    assert result.status == "ok" and result.model is None and not result.ledger_refs
    assert result.method == name and result.config_sha256 == method.config_sha256
    assert result.domain_payload["evidence_refs"]
    assert all(args.get("source_id", "toy") == "toy" for _, args in transport.calls)
    assert all(
        not {"gold", "label_payload", "start_target", "trace_marker"}.intersection(args)
        for _, args in transport.calls
    )
    assert method.metrics_by_item[PUBLIC.item_id].attempted_calls == len(transport.calls)
    assert method.metrics_by_item[PUBLIC.item_id].returned_calls == len(transport.calls)
    assert method.metrics_by_item[PUBLIC.item_id].measured_read_bytes == 17 * len(transport.calls)


def test_scripted_sequence_is_four_calls_with_observed_anchor():
    transport = ToyTransport()
    method = make_method("s1_scripted", transport)
    method.predict(PUBLIC)
    assert [name for name, _ in transport.calls] == [
        "list_sources",
        "errors",
        "search",
        "read_range",
    ]
    assert transport.calls[-1][1] == {"source_id": "toy", "start_line": 105, "end_line": 130}


def test_naive_uses_actual_last_returned_line_after_frame_truncation():
    class Short(ToyTransport):
        def envelope(self, tool, arguments):
            value = super().envelope(tool, arguments)
            if arguments.get("start_line") == 1:
                return value.model_copy(
                    update={"lines": value.lines[:5], "truncation": Truncation(output_bytes=True)}
                )
            return value

    transport = Short()
    method = make_method("naive_paged_range", transport)
    method.predict(PUBLIC)
    assert [args["start_line"] for _, args in transport.calls] == [1, 6, 106]


def test_grep_cursor_cycle_fails_with_exact_attempt_count():
    class Cycle(ToyTransport):
        def envelope(self, tool, arguments):
            return super().envelope(tool, arguments).model_copy(update={"next_cursor": "repeat"})

    transport = Cycle()
    method = make_method("redacted_grep_range", transport)
    result = method.predict(PUBLIC)
    assert result.status == "blocked" and result.issues == ("pagination_no_progress",)
    assert len(transport.calls) == 2


def test_call_budget_prevents_extra_dispatch_and_is_in_config_identity():
    transport = ToyTransport()
    method = make_method("s1_scripted", transport, max_calls=1)
    result = method.predict(PUBLIC)
    assert result.status == "blocked" and len(transport.calls) == 1
    assert result.domain_payload is None and not result.source_refs
    other = make_method("s1_scripted", ToyTransport(), max_calls=2)
    assert method.config_sha256 != other.config_sha256


def test_unmeasured_read_counter_stays_unknown():
    method = make_method("redacted_grep_range", ToyTransport(measured=None))
    method.predict(PUBLIC)
    metrics = method.metrics_by_item[PUBLIC.item_id]
    assert metrics.measured_read_bytes is None and metrics.observed_frame_bytes > 0
    assert metrics.frame_origins == ("adapter_serialization",)


def test_late_response_counts_but_cannot_score_as_timely_success():
    now = [0.0]

    class Late(ToyTransport):
        def __call__(self, tool, arguments):
            observed = super().__call__(tool, arguments)
            now[0] += 6
            return observed

    method = make_method("s1_scripted", Late(), clock=lambda: now[0])
    result = method.predict(PUBLIC)
    metrics = method.metrics_by_item[PUBLIC.item_id]
    assert result.status == "blocked" and result.domain_payload is None
    assert (metrics.attempted_calls, metrics.returned_calls) == (1, 1)
    assert metrics.observed_frame_bytes > 0 and metrics.elapsed_seconds == 6


def test_transport_exception_does_not_echo_details_or_invent_measured_reads():
    def fail(_tool, _args):
        raise OSError("private source detail must not be echoed")

    method = make_method("s1_scripted", fail)
    result = method.predict(PUBLIC)
    assert result.status == "unavailable" and result.issues == ("transport_unavailable",)
    assert "private source" not in result.model_dump_json()
    metrics = method.metrics_by_item[PUBLIC.item_id]
    assert (metrics.attempted_calls, metrics.returned_calls, metrics.measured_read_bytes) == (
        1,
        0,
        None,
    )


def test_source_request_escape_is_blocked_before_transport():
    transport = ToyTransport()
    store = EvidenceStore({"toy": SOURCE})
    client = RecordingClient("toy_case", "s1_scripted", "toy", transport, store)
    with pytest.raises(MethodCallError, match="cross_source_request"):
        client.call("tail", {"source_id": "other", "lines": 1})
    assert not transport.calls and client.metrics().attempted_calls == 0


def test_generation_change_is_stale_with_all_calls_retained():
    class Changed(ToyTransport):
        def envelope(self, tool, arguments):
            value = super().envelope(tool, arguments)
            return (
                value.model_copy(update={"generation_id": "other_generation"})
                if tool == "search"
                else value
            )

    transport = Changed()
    method = make_method("s1_scripted", transport)
    result = method.predict(PUBLIC)
    assert result.status == "stale" and result.issues == ("generation_changed",)
    assert len(transport.calls) == 3


def test_private_payload_rejected_before_factory_or_tool():
    def forbidden(*_args):
        pytest.fail("private input reached factory")

    method = FixedMethod("s1_scripted", forbidden, "e" * 64)
    bad = PUBLIC.model_copy(
        update={"public_payload": {**PUBLIC.public_payload, "trace_marker": "private"}}
    )
    with pytest.raises(ValueError):
        method.predict(bad)


def test_repeated_case_never_silently_executes_again():
    transport = ToyTransport()
    method = make_method("s1_scripted", transport)
    method.predict(PUBLIC)
    count = len(transport.calls)
    with pytest.raises(ValueError, match="already_attempted"):
        method.predict(PUBLIC)
    assert len(transport.calls) == count


@pytest.mark.parametrize("hint", ["(.*)+ ?!", "接口异常 重试失败", "the and with", "αβγ " * 100])
def test_pattern_is_bounded_and_literal_not_an_injected_regex(hint):
    pattern = symptom_pattern(hint)
    assert 0 < len(pattern.encode("utf-8")) <= 512
    Matcher(pattern)  # Actual installed RE2 wrapper; no Python-regex compatibility claim.


def test_wrong_factory_budget_is_not_accepted_under_same_config():
    transport = ToyTransport()
    store = EvidenceStore({"toy": SOURCE})
    method = FixedMethod(
        "s1_scripted",
        lambda i, m, s: RecordingClient(i, m, s, transport, store, max_calls=1),
        "e" * 64,
    )
    with pytest.raises(ValueError, match="budget_binding"):
        method.predict(PUBLIC)
    assert not transport.calls


@pytest.mark.parametrize("name", METHODS)
def test_method_predictions_resolve_through_actual_canonical_domain_adapter(name):
    store = EvidenceStore({"toy": SOURCE})
    transport = ToyTransport()
    method = FixedMethod(name, lambda i, m, s: RecordingClient(i, m, s, transport, store), "e" * 64)
    result = method.predict(PUBLIC)
    gold = GoldRecord.model_validate_json(
        canonical_bytes(
            {
                "item_id": "toy_case",
                "dataset": "toy_dataset",
                "group_id": "toy_group",
                "split": "dev",
                "label_version": "toy_v1",
                "source_ref": SOURCE.model_dump(mode="json"),
                "input_sha256": PUBLIC.input_sha256,
                "label_source": "synthetic",
                "label_provenance_ref": "toy_author",
                "domain_kind": "log_incident/1",
                "label_payload": {
                    "kind": "domain_labels",
                    "payload": {
                        "source_id": "toy",
                        "start_line": 110,
                        "end_line": 110,
                        "trace_marker": "toy_trace",
                    },
                },
            }
        )
    )
    adapter = IncidentAdapter({PUBLIC.item_id: PUBLIC}, store)
    adapter.validate_prediction(result)
    assert adapter.to_outcomes(result, gold, None)[0].correct is True


def test_naive_empty_source_abstains_with_one_observed_call():
    transport = ToyTransport()
    transport.total = 0
    method = make_method("naive_paged_range", transport)
    result = method.predict(PUBLIC)
    assert result.status == "abstained" and len(transport.calls) == 1


def test_unavailable_catalog_source_prevents_data_calls():
    class Unreadable(ToyTransport):
        def envelope(self, tool, arguments):
            return ToolEnvelope(
                ok=True, sources=[SourceInfo(id="toy", display_path="toy.log", readable=False)]
            )

    transport = Unreadable()
    method = make_method("s1_scripted", transport)
    result = method.predict(PUBLIC)
    assert result.status == "unavailable" and len(transport.calls) == 1
