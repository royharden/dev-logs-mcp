"""Original toy controls; never the independently sealed DEV/heldout corpus."""

import json

import pytest

from dev_logs_mcp.evaluation.domain import EvidenceStore, IncidentAdapter, IncidentLabel
from dev_logs_mcp.shared.evalkit.identity import canonical_bytes
from dev_logs_mcp.shared.evalkit.models import GoldRecord, Prediction, PublicMethodInput, SourceRef
from dev_logs_mcp.shared.evalkit.reporting import metric_row
from dev_logs_mcp.shared.evalkit.runner import SourceView
from dev_logs_mcp.shared.evalkit.statistics import accuracy
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.conformance.cases import Observation
from dev_logs_mcp.shared.mcpkit.errors import ErrorCode, ToolError
from dev_logs_mcp.shared.mcpkit.models import LogLine, ToolEnvelope

METHOD = "s1_scripted"
SOURCE = SourceRef(handle="toy_source", sha256="a" * 64)
PUBLIC = PublicMethodInput.model_validate_json(
    canonical_bytes(
        {
            "item_id": "toy_case",
            "input_sha256": "b" * 64,
            "public_payload": {"source_id": "toy", "symptom_hint": "Toy operation failed"},
            "public_config_refs": [],
        }
    )
)
GOLD = GoldRecord.model_validate_json(
    canonical_bytes(
        {
            "item_id": "toy_case",
            "dataset": "toy_dataset",
            "group_id": "toy_group",
            "split": "dev",
            "label_version": "toy_v1",
            "source_ref": SOURCE.model_dump(mode="json"),
            "input_sha256": "b" * 64,
            "label_source": "synthetic",
            "label_provenance_ref": "toy_author",
            "domain_kind": "log_incident/1",
            "label_payload": {
                "kind": "domain_labels",
                "payload": {
                    "source_id": "toy",
                    "start_line": 10,
                    "end_line": 12,
                    "trace_marker": "trace_toy",
                },
            },
        }
    )
)


def setup_store(**kwargs):
    store = EvidenceStore({"toy": SOURCE}, **kwargs)
    return store, IncidentAdapter({PUBLIC.item_id: PUBLIC}, store)


def frame(text="trace_toy failed", *, line=11, omitted=None, source="toy", request_id=7):
    envelope = ToolEnvelope(
        ok=True,
        source_id=source,
        generation_id="toy_generation",
        lines=[LogLine(line_no=line, byte_offset=100, text=text, omitted=omitted)],
    )
    return Observation(
        frame=OutputBudget().render(envelope, request_id).wire_bytes,
        frame_origin="adapter_serialization",
        request_id=request_id,
    )


def prediction(refs=(), *, status="ok", item_id="toy_case", method=METHOD, sources=(SOURCE,)):
    return Prediction.model_validate_json(
        canonical_bytes(
            {
                "item_id": item_id,
                "method": method,
                "method_version": "toy_v1",
                "config_sha256": "c" * 64,
                "model": None,
                "origin": "synthetic",
                "status": status,
                "domain_payload": {"evidence_refs": list(refs)} if status == "ok" else None,
                "machine_output": None,
                "human_effective_output": None,
                "human_provenance_ref": None,
                "issues": [],
                "ledger_refs": [],
                "source_refs": [r.model_dump(mode="json") for r in sources]
                if status == "ok"
                else [],
            }
        )
    )


def test_observed_source_interval_trace_required_for_success():
    store, adapter = setup_store()
    ref = store.record("toy_case", METHOD, "read_range", frame())
    (outcome,) = adapter.to_outcomes(prediction([ref]), GOLD, None)
    assert outcome.correct is True and outcome.predicted is True
    assert outcome.expected is True  # Private output contains no target coordinates/trace.


def test_error_group_trace_is_actual_observed_evidence():
    store, adapter = setup_store()
    envelope = ToolEnvelope.model_validate_json(
        canonical_bytes(
            {
                "ok": True,
                "source_id": "toy",
                "generation_id": "toy_generation",
                "groups": [
                    {
                        "signature": "toy error",
                        "level": "ERROR",
                        "occurrence_count_in_coverage": 1,
                        "first_in_coverage": {"line_no": 10, "byte_offset": 90, "text": "failed"},
                        "trace": [{"line_no": 11, "byte_offset": 100, "text": "trace_toy"}],
                    }
                ],
            }
        )
    )
    observed = Observation(
        frame=OutputBudget().render(envelope, 9).wire_bytes,
        frame_origin="adapter_serialization",
        request_id=9,
    )
    ref = store.record("toy_case", METHOD, "errors", observed)
    assert adapter.to_outcomes(prediction([ref]), GOLD, None)[0].correct is True


def test_match_coordinates_without_returned_text_do_not_locate():
    store, adapter = setup_store()
    envelope = ToolEnvelope.model_validate_json(
        canonical_bytes(
            {
                "ok": True,
                "source_id": "toy",
                "generation_id": "toy_generation",
                "matches": [{"line_no": 11}],
            }
        )
    )
    observed = Observation(
        frame=OutputBudget().render(envelope, 9).wire_bytes,
        frame_origin="adapter_serialization",
        request_id=9,
    )
    ref = store.record("toy_case", METHOD, "search", observed)
    assert adapter.to_outcomes(prediction([ref]), GOLD, None)[0].correct is False


def test_trace_on_different_outside_line_cannot_validate_target_coordinates():
    store, adapter = setup_store()
    envelope = ToolEnvelope(
        ok=True,
        source_id="toy",
        generation_id="toy_generation",
        lines=[
            LogLine(line_no=11, byte_offset=100, text="different event"),
            LogLine(line_no=14, byte_offset=200, text="trace_toy"),
        ],
    )
    observed = Observation(
        frame=OutputBudget().render(envelope, 9).wire_bytes,
        frame_origin="adapter_serialization",
        request_id=9,
    )
    ref = store.record("toy_case", METHOD, "read_range", observed)
    assert adapter.to_outcomes(prediction([ref]), GOLD, None)[0].correct is False


@pytest.mark.parametrize(
    "line,text,omitted",
    [
        (9, "trace_toy failed", None),
        (13, "trace_toy failed", None),
        (11, "a different operation failed", None),
        (11, "trace_toy failed", "private_key"),
        (11, "trace_toy failed", "overlong_line"),
    ],
    ids=["before", "after", "wrong_trace", "private_omission", "long_omission"],
)
def test_coordinates_or_omitted_content_do_not_fabricate_located(line, text, omitted):
    store, adapter = setup_store()
    ref = store.record("toy_case", METHOD, "read_range", frame(text, line=line, omitted=omitted))
    assert adapter.to_outcomes(prediction([ref]), GOLD, None)[0].correct is False


@pytest.mark.parametrize(
    "item_id,method", [("other_case", METHOD), ("toy_case", "naive_paged_range")]
)
def test_known_receipt_cannot_be_transplanted_across_case_or_method(item_id, method):
    store, adapter = setup_store()
    ref = store.record(item_id, method, "read_range", frame())
    with pytest.raises(ValueError, match="cross_case"):
        adapter.validate_prediction(prediction([ref]))


def test_fabricated_unknown_reference_and_raw_coordinates_rejected():
    _, adapter = setup_store()
    with pytest.raises(ValueError, match="cross_case"):
        adapter.validate_prediction(prediction(["d" * 64]))
    altered = prediction(["d" * 64]).model_copy(
        update={"domain_payload": {"start_line": 10, "trace_marker": "trace_toy"}}
    )
    with pytest.raises(ValueError):
        adapter.validate_prediction(altered)


def test_mutated_mirror_and_wrong_request_id_rejected():
    store, _ = setup_store()
    observed = frame()
    raw = json.loads(observed.frame)
    raw["result"]["content"][0]["text"] = "{}"
    with pytest.raises(ValueError, match="invalid_recorded_response"):
        store.record(
            "toy_case",
            METHOD,
            "read_range",
            observed.model_copy(update={"frame": canonical_bytes(raw)}),
        )
    with pytest.raises(ValueError, match="invalid_recorded_response"):
        store.record(
            "toy_case", METHOD, "read_range", observed.model_copy(update={"request_id": 8})
        )


def test_failed_tool_response_can_be_recorded_but_never_locates():
    store, adapter = setup_store()
    envelope = ToolEnvelope(
        ok=False,
        error=ToolError(
            code=ErrorCode.UNKNOWN_SOURCE,
            message="The configured source is unavailable",
            hint="Check ID",
        ),
    )
    observed = Observation(
        frame=OutputBudget().render(envelope, 10).wire_bytes,
        frame_origin="adapter_serialization",
        request_id=10,
    )
    ref = store.record("toy_case", METHOD, "read_range", observed)
    assert adapter.to_outcomes(prediction([ref], sources=()), GOLD, None)[0].correct is False


def test_reported_read_over_budget_frame_is_not_accepted_evidence():
    store, _ = setup_store()
    observed = frame().model_copy(update={"measured_read_bytes": 8 * 1024 * 1024 + 1})
    with pytest.raises(ValueError, match="invalid_recorded_response"):
        store.record("toy_case", METHOD, "read_range", observed)


def test_stale_public_source_view_cannot_be_projected():
    _, adapter = setup_store()
    with pytest.raises(ValueError, match="view_mismatch"):
        adapter.to_public_input(
            GOLD, SourceView("available", "f" * 64, dict(PUBLIC.public_payload))
        )


def test_uncorrelated_observation_and_unknown_source_rejected():
    store, _ = setup_store()
    with pytest.raises(ValueError, match="record_refused"):
        store.record(
            "toy_case", METHOD, "read_range", frame().model_copy(update={"request_id": None})
        )
    with pytest.raises(ValueError, match="invalid_recorded_response"):
        store.record("toy_case", METHOD, "read_range", frame(source="unconfigured"))


def test_protocol_frame_and_store_bounds_are_not_bypassable():
    store, _ = setup_store(max_records=1)
    store.record("toy_case", METHOD, "read_range", frame())
    with pytest.raises(ValueError, match="record_refused"):
        store.record("toy_case", METHOD, "read_range", frame())
    store, _ = setup_store()
    oversized = frame().model_copy(update={"frame": b" " * 32769})
    with pytest.raises(ValueError, match="invalid_recorded_response"):
        store.record("toy_case", METHOD, "read_range", oversized)


def test_frozen_source_reference_mismatch_never_scores():
    store, adapter = setup_store()
    ref = store.record("toy_case", METHOD, "read_range", frame())
    bad_ref = SourceRef(handle="toy_source", sha256="f" * 64)
    with pytest.raises(ValueError, match="source_refs_mismatch"):
        adapter.validate_prediction(prediction([ref], sources=(bad_ref,)))
    with pytest.raises(ValueError, match="binding_mismatch"):
        adapter.validate_gold(GOLD.model_copy(update={"source_ref": bad_ref}))


def test_public_input_projection_never_receives_gold_and_cannot_mutate_frozen_copy():
    _, adapter = setup_store()
    view = SourceView("available", PUBLIC.input_sha256, dict(PUBLIC.public_payload))
    public = adapter.to_public_input(GOLD, view)
    assert set(public.public_payload) == {"source_id", "symptom_hint"}
    assert "trace_toy" not in canonical_bytes(public.model_dump(mode="json")).decode()
    public.public_payload["symptom_hint"] = "changed by runner"
    assert adapter.to_public_input(GOLD, view).public_payload == PUBLIC.public_payload
    for value in (
        {"source_id": "toy", "symptom_hint": "hint", "group_id": "hidden"},
        {"source_id": "other", "symptom_hint": "hint"},
    ):
        with pytest.raises(ValueError, match="view_mismatch"):
            adapter.to_public_input(GOLD, SourceView("available", PUBLIC.input_sha256, value))


@pytest.mark.parametrize(
    "status", ["abstained", "blocked", "invalid", "provider_error", "stale", "unavailable"]
)
def test_every_non_success_remains_eligible_false(status):
    _, adapter = setup_store()
    (outcome,) = adapter.to_outcomes(prediction(status=status), GOLD, None)
    assert (outcome.eligibility, outcome.correct, outcome.status) == ("eligible", False, status)


def test_invalid_prediction_payload_not_rescored_as_success():
    store, adapter = setup_store()
    ref = store.record("toy_case", METHOD, "read_range", frame())
    invalid = prediction([ref]).model_copy(update={"status": "invalid"})
    assert adapter.to_outcomes(invalid, GOLD, None)[0].correct is False


def test_actual_canonical_accuracy_keeps_error_abstention_and_miss_denominator():
    store, adapter = setup_store()
    hit = store.record("toy_case", METHOD, "read_range", frame())
    miss = store.record("toy_case", METHOD, "read_range", frame("not the target"))
    outcomes = [
        adapter.to_outcomes(prediction([hit]), GOLD, None)[0],
        adapter.to_outcomes(prediction([miss]), GOLD, None)[0],
        adapter.to_outcomes(prediction(status="abstained"), GOLD, None)[0],
        adapter.to_outcomes(prediction(status="unavailable"), GOLD, None)[0],
    ]
    outcomes = tuple(
        row.model_copy(update={"item_id": f"toy_{i}"}) for i, row in enumerate(outcomes)
    )
    (spec,) = adapter.metric_specs()
    result = metric_row(
        outcomes,
        tuple(r.item_id for r in outcomes),
        spec,
        accuracy,
        method=METHOD,
        dataset_alias="toy",
        split="dev",
        config_ref="toy_config",
    )
    assert (result.numerator, result.denominator, result.corpus_N, result.value) == (1, 4, 4, 0.25)
    assert (result.error_N, result.abstention_N) == (1, 1)


def test_strict_label_refuses_boolean_and_inverted_interval():
    for start, end in [(True, 12), (12, 10)]:
        with pytest.raises(ValueError):
            IncidentLabel(source_id="toy", start_line=start, end_line=end, trace_marker="toy")


def test_never_run_remains_unmeasured_not_false_execution():
    _, adapter = setup_store()
    value = prediction(status="abstained").model_copy(
        update={"status": "not_run", "origin": "not_run"}
    )
    (outcome,) = adapter.to_outcomes(value, GOLD, None)
    assert outcome.correct is None and outcome.predicted is None
    assert outcome.status == outcome.evidence_origin == "not_run"
