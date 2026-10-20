"""Handcrafted in-memory controls, never sealed campaign data or native execution."""

from dataclasses import replace

import pytest

from dev_logs_mcp.evaluation.controller import (
    Admission,
    digest,
    evaluate,
    implementation_digest,
    input_bundle_digest,
    method_config_hashes,
)
from dev_logs_mcp.evaluation.domain import METHODS, EvidenceStore, IncidentAdapter
from dev_logs_mcp.shared.evalkit.identity import canonical_bytes, ordered_ids_digest
from dev_logs_mcp.shared.evalkit.models import GoldRecord, Manifest, PublicMethodInput, SourceRef
from dev_logs_mcp.shared.evalkit.runner import HeldoutAdmission, HeldoutHistory, SourceView
from dev_logs_mcp.shared.mcpkit.bounded_output import OutputBudget
from dev_logs_mcp.shared.mcpkit.conformance.cases import Observation
from dev_logs_mcp.shared.mcpkit.models import Coverage, LogLine, Match, SourceInfo, ToolEnvelope

COMMIT = "1" * 40


@pytest.fixture(autouse=True)
def forbid_effects(monkeypatch):
    """what_bug_this_catches: a controller must not acquire source/provider access."""

    def forbidden(*_args, **_kwargs):
        pytest.fail("unexpected process, network, corpus or source acquisition")

    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("os.system", forbidden)
    monkeypatch.setattr("ctypes.WinDLL", forbidden, raising=False)
    monkeypatch.setattr("dev_logs_mcp.shared.evalkit.corpus.load_corpus", forbidden)
    monkeypatch.setattr(
        "dev_logs_mcp.shared.mcpkit.safe_path.SafePathPolicy.open_source", forbidden
    )


def job(split="dev"):
    """One original handwritten case; no fixture file or generator is involved."""
    source = SourceRef(handle="handcrafted_handle", sha256="a" * 64)
    public = PublicMethodInput.model_validate_json(
        canonical_bytes(
            {
                "item_id": "handcrafted_case",
                "input_sha256": "b" * 64,
                "public_config_refs": [],
                "public_payload": {"source_id": "handcrafted", "symptom_hint": "operation failed"},
            }
        )
    )
    record = GoldRecord.model_validate_json(
        canonical_bytes(
            {
                "item_id": public.item_id,
                "dataset": "handcrafted_dataset",
                "group_id": "handcrafted_group",
                "split": split,
                "label_version": "handcrafted_v1",
                "source_ref": source.model_dump(),
                "input_sha256": public.input_sha256,
                "label_source": "synthetic",
                "label_provenance_ref": "handwritten_control",
                "domain_kind": "log_incident/1",
                "label_payload": {
                    "kind": "domain_labels",
                    "payload": {
                        "source_id": "handcrafted",
                        "start_line": 2,
                        "end_line": 2,
                        "trace_marker": "handcrafted_trace",
                    },
                },
            }
        )
    )
    sources, publics = {"handcrafted": source}, {public.item_id: public}
    adapter = IncidentAdapter(publics, EvidenceStore(sources))
    pinned = {"status": "available", "ref": "handcrafted_reference", "sha256": "c" * 64}
    manifest = Manifest.model_validate_json(
        canonical_bytes(
            {
                "manifest_id": "handcrafted_manifest",
                "parent_manifest_sha256": None,
                "split_seed": 1,
                "partition_provenance": "seeded",
                "frozen_at": "2026-01-01T00:00:00Z",
                "scorer_version": "handcrafted_v1",
                "comparator_config": pinned,
                "domain_adapter_ref": pinned,
                "experiment_refs": {"heldout_seal": pinned, "dev_config_lock": pinned},
                "splits": [
                    {
                        "split": split,
                        "items_file": "unused.jsonl",
                        "item_count": 1,
                        "ordered_item_ids": [public.item_id],
                        "items_sha256": "d" * 64,
                        "ordered_ids_sha256": ordered_ids_digest((public.item_id,)),
                        "group_ids": [record.group_id],
                    }
                ],
                "group_split_map": {record.group_id: split},
                "group_members": {record.group_id: [public.item_id]},
                "source_artifacts": [
                    {
                        "namespace": "handcrafted_source",
                        "status": "available",
                        "sha256": source.sha256,
                        "count": 1,
                        "member_ids": [public.item_id],
                    }
                ],
                "publication_policy": adapter.public_projection_policy().model_dump(mode="json"),
                "run_history_ref": "handcrafted_history",
            }
        )
    )
    implementation = implementation_digest()
    admission = Admission(
        COMMIT,
        digest(manifest.model_dump(mode="json")),
        implementation,
        input_bundle_digest((record,), publics, sources),
        method_config_hashes(implementation),
    )
    return dict(
        admission=admission,
        observed_candidate_commit=COMMIT,
        manifest=manifest,
        split=split,
        records=(record,),
        public_inputs=publics,
        sources=sources,
        source_views={
            public.item_id: SourceView("available", public.input_sha256, public.public_payload)
        },
    )


class HandcraftedTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, tool, arguments):
        self.calls.append((tool, dict(arguments)))
        row = LogLine(line_no=2, byte_offset=10, text="operation failed handcrafted_trace")
        if tool == "list_sources":
            envelope = ToolEnvelope(
                ok=True,
                sources=[
                    SourceInfo(
                        id="handcrafted",
                        display_path="handcrafted.log",
                        readable=True,
                    )
                ],
            )
        else:
            envelope = ToolEnvelope(
                ok=True,
                source_id="handcrafted",
                generation_id="handcrafted_generation",
                lines=[] if tool == "errors" else [row],
                matches=[Match(line_no=2)] if tool == "search" else [],
                coverage=Coverage(total_lines=2, first_line=2, last_line=2),
            )
        request_id = len(self.calls)
        return Observation(
            frame=OutputBudget().render(envelope, request_id).wire_bytes,
            frame_origin="adapter_serialization",
            request_id=request_id,
            measured_read_bytes=None,
        )


def test_default_does_not_construct_transport_or_invent_measurements():
    result = evaluate(**job(), transport_factory=lambda *_: pytest.fail("dispatch"))
    assert all(
        row.measurement_status == "not_measured" and row.value is None for row in result.metric_rows
    )
    assert all(not value for value in result.call_metrics.values())
    assert all(not method.actual_predictions for method in result.comparison.methods.values())


def test_same_fixed_cases_public_inputs_and_private_aggregate_boundary():
    received, transports = [], {}

    def factory(item, method, source):
        received.append((item, method, source))
        transports[method] = HandcraftedTransport()
        return transports[method]

    result = evaluate(**job(), execute=True, transport_factory=factory)
    assert {method for _, method, _ in received} == set(METHODS)
    assert all(
        item == "handcrafted_case" and source == "handcrafted" for item, _, source in received
    )
    assert all(row.value == 1 and row.denominator == 1 for row in result.metric_rows)
    for method, transport in transports.items():
        metrics = result.call_metrics[method]["handcrafted_case"]
        assert metrics.attempted_calls == metrics.returned_calls == len(transport.calls)
        assert metrics.measured_read_bytes is None and metrics.observed_frame_bytes > 0
        assert metrics.frame_origins == ("adapter_serialization",)
    public = canonical_bytes(result.public_aggregates())
    assert all(
        secret not in public
        for secret in (
            b"handcrafted_case",
            b"handcrafted_handle",
            b"handcrafted_trace",
            b"handcrafted_dataset",
        )
    )
    assert all(
        set(row)
        == {
            "method",
            "split",
            "metric",
            "value",
            "numerator",
            "denominator",
            "corpus_N",
            "eligible_N",
            "answered_N",
            "error_N",
            "abstention_N",
            "stale_N",
        }
        for row in result.public_aggregates()
    )


@pytest.mark.parametrize("pin", ["candidate", "manifest", "implementation", "input", "config"])
def test_changed_admission_fails_before_dispatch(pin):
    values = job()
    changes = {
        "candidate": {"candidate_commit": "2" * 40},
        "manifest": {"manifest_sha256": "0" * 64},
        "implementation": {"implementation_sha256": "0" * 64},
        "input": {"input_bundle_sha256": "0" * 64},
        "config": {"method_config_sha256": {}},
    }
    values["admission"] = replace(values["admission"], **changes[pin])
    with pytest.raises(ValueError, match="changed"):
        evaluate(**values, execute=True, transport_factory=lambda *_: pytest.fail("dispatch"))


def test_tampered_private_label_is_bound_by_input_admission():
    values = job()
    wire = values["records"][0].model_dump(mode="json")
    wire["label_payload"]["payload"]["trace_marker"] = "changed"
    values["records"] = (GoldRecord.model_validate_json(canonical_bytes(wire)),)
    with pytest.raises(ValueError, match="admission_changed"):
        evaluate(**values, execute=True, transport_factory=lambda *_: pytest.fail("dispatch"))


@pytest.mark.parametrize("status", ["stale", "unavailable", "wrong_hash"])
def test_source_failures_keep_fixed_denominator_without_transport(status):
    values = job()
    values["source_views"] = {
        "handcrafted_case": SourceView(
            "available" if status == "wrong_hash" else status,
            "0" * 64,
            {},
        )
    }
    result = evaluate(**values, execute=True, transport_factory=lambda *_: pytest.fail("dispatch"))
    assert all(row.denominator == 1 and row.value == 0 for row in result.metric_rows)
    assert all(not metrics for metrics in result.call_metrics.values())


def test_mismatched_available_payload_is_rejected_before_first_method():
    values = job()
    values["source_views"] = {
        "handcrafted_case": SourceView(
            "available",
            "b" * 64,
            {"source_id": "handcrafted", "symptom_hint": "changed"},
        )
    }
    with pytest.raises(ValueError, match="public_source_view_mismatch"):
        evaluate(**values, execute=True, transport_factory=lambda *_: pytest.fail("dispatch"))


@pytest.mark.parametrize("failure", ["factory", "transport", "invalid_reply"])
def test_failed_attempts_are_retained_even_without_valid_evidence(failure):
    def factory(*_):
        if failure == "factory":
            raise OSError("private factory detail")

        def transport(*_):
            if failure == "transport":
                raise OSError("private transport detail")
            return Observation(frame=b"{}", frame_origin="adapter_serialization", request_id=1)

        return transport

    result = evaluate(**job(), execute=True, transport_factory=factory)
    assert all(row.value == 0 and row.denominator == row.error_N == 1 for row in result.metric_rows)
    for metrics in result.call_metrics.values():
        row = metrics["handcrafted_case"]
        assert row.attempted_calls == 1 and row.measured_read_bytes is None
        assert row.returned_calls == (1 if failure == "invalid_reply" else 0)
    assert b"private" not in canonical_bytes(result.public_aggregates())


class History(HeldoutHistory):
    def __init__(self):
        self.calls = []

    def record_exposure(self, admission):
        if self.calls:
            raise ValueError("handcrafted_exposure_already_used")
        self.calls.append(admission)


def test_heldout_requires_exact_candidate_and_durable_admission_before_dispatch():
    values = job("heldout")

    def factory(*_):
        return HandcraftedTransport()

    with pytest.raises(ValueError, match="heldout_admission_required"):
        evaluate(**values, execute=True, transport_factory=lambda *_: pytest.fail("dispatch"))
    admission = HeldoutAdmission(
        values["admission"].manifest_sha256,
        "c" * 64,
        "c" * 64,
        dict(values["admission"].method_config_sha256),
        COMMIT,
        "handcrafted_history",
        None,
    )
    history = History()
    with pytest.raises(ValueError, match="heldout_candidate_changed"):
        evaluate(
            **values,
            execute=True,
            transport_factory=lambda *_: pytest.fail("dispatch"),
            heldout_admission=replace(admission, candidate_commit="2" * 40),
            heldout_history=history,
        )

    assert history.calls == []
    result = evaluate(
        **values,
        execute=True,
        transport_factory=factory,
        heldout_admission=admission,
        heldout_history=history,
    )
    assert len(history.calls) == 1 and all(row.value == 1 for row in result.metric_rows)
    with pytest.raises(ValueError, match="exposure_already_used"):
        evaluate(
            **values,
            execute=True,
            transport_factory=lambda *_: pytest.fail("dispatch"),
            heldout_admission=admission,
            heldout_history=history,
        )


def test_configuration_entrypoint_is_in_process_and_not_measured(capsys):
    import json
    import runpy
    from pathlib import Path

    entry = Path(__file__).parents[2] / "scripts" / "eval.py"
    main = runpy.run_path(str(entry))["main"]
    assert main(["--preflight"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "not_measured"
    assert output["implementation_sha256"] == implementation_digest()
    assert set(output["method_config_sha256"]) == set(METHODS)
