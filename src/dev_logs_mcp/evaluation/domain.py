"""Private incident scoring from recorded responses and canonical S2 wires.

The caller owns actual transport capture, frozen-source provenance and exposure
authority. Recording a supplied frame does not establish those facts. No source
acquisition, policy execution, generic statistics or corpus enrichment lives here.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from pydantic import Field, model_validator

from ..shared.evalkit.identity import canonical_bytes
from ..shared.evalkit.models import (
    DomainLabels,
    GoldRecord,
    MetricSpec,
    Outcome,
    Prediction,
    PublicMethodInput,
    PublicProjectionPolicy,
    SourceRef,
)
from ..shared.evalkit.runner import SourceView
from ..shared.mcpkit.conformance.cases import Case, Observation
from ..shared.mcpkit.conformance.runner import inspect
from ..shared.mcpkit.errors import MAX_FRAME_BYTES, BoundaryModel
from ..shared.mcpkit.models import LogLine, SourceId, ToolEnvelope

METHODS = ("s1_scripted", "redacted_grep_range", "naive_paged_range")
TOOLS = frozenset({"list_sources", "tail", "search", "read_range", "errors"})


class IncidentLabel(BoundaryModel):
    source_id: SourceId
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    trace_marker: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def ordered(self):
        if self.end_line < self.start_line:
            raise ValueError("invalid_incident_interval")
        return self


class PublicSymptom(BoundaryModel):
    source_id: SourceId
    symptom_hint: str = Field(min_length=1, max_length=512)


class EvidenceSelection(BoundaryModel):
    evidence_refs: list[str] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique_references(self):
        if len(set(self.evidence_refs)) != len(self.evidence_refs) or any(
            len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
            for value in self.evidence_refs
        ):
            raise ValueError("invalid_evidence_references")
        return self


@dataclass(frozen=True)
class _Witness:
    item_id: str
    method: str
    source_id: str | None
    source_ref: SourceRef | None
    generation_id: str | None
    rows: tuple[LogLine, ...] = field(repr=False)
    frame_sha256: str
    frame_origin: str
    frame_bytes: int
    measured_read_bytes: int | None


class EvidenceStore:
    """Controller-owned response receipts; never pass this object to predict()."""

    def __init__(self, sources: Mapping[str, SourceRef], *, max_records=4096, max_bytes=16 << 20):
        if (
            not sources
            or len(sources) > 100
            or type(max_records) is not int
            or not 1 <= max_records <= 4096
            or type(max_bytes) is not int
            or not MAX_FRAME_BYTES <= max_bytes <= 64 << 20
        ):
            raise ValueError("invalid_evidence_store_bounds")
        for source_id, reference in sources.items():
            PublicSymptom(source_id=source_id, symptom_hint="source_binding")
            if not isinstance(reference, SourceRef) or reference.sha256 is None:
                raise ValueError("frozen_source_hash_required")
        self._sources = dict(sources)
        self._records: dict[str, _Witness] = {}
        self._bytes = 0
        self._max_records, self._max_bytes = max_records, max_bytes

    def record(self, item_id: str, method: str, tool: str, observation: Observation) -> str:
        """Capture an already returned frame; this method never calls a tool.

        Costs/attempts are recorded by the execution controller even if this
        bounded evidence store refuses a frame. The store is not a call ledger.
        """
        if (
            not item_id
            or len(item_id) > 512
            or method not in METHODS
            or tool not in TOOLS
            or observation.request_id is None
            or len(self._records) >= self._max_records
            or self._bytes + len(observation.frame) > self._max_bytes
        ):
            raise ValueError("evidence_record_refused")
        try:
            raw = json.loads(observation.frame)
            envelope = ToolEnvelope.model_validate_json(
                canonical_bytes(raw["result"]["structuredContent"])
            )
            case = Case(
                case_id="evidence",
                what_bug_this_catches="Reject uncorrelated or mismatched recorded output",
                tool=tool,
                expect_error=envelope.error.code.value if envelope.error else None,
            )
            if (
                inspect(
                    case,
                    observation,
                    lambda _case, value: ToolEnvelope.model_validate_json(canonical_bytes(value)),
                )
                != "ok"
            ):
                raise ValueError
            reference = self._sources.get(envelope.source_id)
            if envelope.source_id is not None and reference is None:
                raise ValueError
        except Exception:
            raise ValueError("invalid_recorded_response") from None
        rows = list(envelope.lines)
        for group in envelope.groups:
            rows.extend((group.first_in_coverage, *group.trace))
        witness = _Witness(
            item_id,
            method,
            envelope.source_id,
            reference,
            envelope.generation_id,
            tuple(rows),
            hashlib.sha256(observation.frame).hexdigest(),
            observation.frame_origin,
            len(observation.frame),
            observation.measured_read_bytes,
        )
        receipt_id = hashlib.sha256(
            canonical_bytes([item_id, method, len(self._records), witness.frame_sha256])
        ).hexdigest()
        self._records[receipt_id] = witness
        self._bytes += len(observation.frame)
        return receipt_id

    def _select(self, item_id: str, method: str, references: list[str]) -> tuple[_Witness, ...]:
        selected = tuple(self._records.get(reference) for reference in references)
        if any(row is None or (row.item_id, row.method) != (item_id, method) for row in selected):
            raise ValueError("unknown_or_cross_case_evidence")
        return selected


class IncidentAdapter:
    """Fixed interval-plus-visible-trace rule; Gold never becomes a policy input."""

    def __init__(self, public_inputs: Mapping[str, PublicMethodInput], evidence: EvidenceStore):
        self._public = {}
        for item_id, value in public_inputs.items():
            if item_id != value.item_id:
                raise ValueError("public_input_identity_mismatch")
            PublicSymptom.model_validate(value.public_payload)
            self._public[item_id] = canonical_bytes(value.model_dump(mode="json"))
        self._evidence = evidence

    def _public_record(self, item_id):
        try:
            return PublicMethodInput.model_validate_json(self._public[item_id])
        except KeyError:
            raise ValueError("public_input_unavailable") from None

    def validate_gold(self, record: GoldRecord) -> None:
        if (
            record.domain_kind != "log_incident/1"
            or record.label_source != "synthetic"
            or not isinstance(record.label_payload, DomainLabels)
        ):
            raise ValueError("unsupported_incident_gold")
        label = IncidentLabel.model_validate(record.label_payload.payload)
        public = self._public_record(record.item_id)
        if (
            public.input_sha256 != record.input_sha256
            or public.public_payload["source_id"] != label.source_id
            or self._evidence._sources.get(label.source_id) != record.source_ref
        ):
            raise ValueError("frozen_incident_binding_mismatch")

    def to_public_input(self, record: GoldRecord, source_view: object) -> PublicMethodInput:
        self.validate_gold(record)
        public = self._public_record(record.item_id)
        if (
            not isinstance(source_view, SourceView)
            or source_view.status != "available"
            or source_view.input_sha256 != public.input_sha256
            or canonical_bytes(source_view.public_payload) != canonical_bytes(public.public_payload)
        ):
            raise ValueError("public_source_view_mismatch")
        return public  # Fresh wire object; a runner cannot mutate frozen input storage.

    def validate_prediction(self, prediction: Prediction) -> None:
        if (
            prediction.model is not None
            or prediction.ledger_refs
            or prediction.human_effective_output is not None
            or prediction.human_provenance_ref is not None
            or prediction.machine_output is not None
            or prediction.origin not in ("synthetic", "not_run")
        ):
            raise ValueError("unsupported_incident_prediction")
        if prediction.status != "ok":
            if prediction.domain_payload is not None or prediction.source_refs:
                raise ValueError("failed_prediction_claims_evidence")
            return
        selection = EvidenceSelection.model_validate(prediction.domain_payload)
        witnesses = self._evidence._select(
            prediction.item_id, prediction.method, selection.evidence_refs
        )
        actual_refs = {row.source_ref for row in witnesses if row.source_ref is not None}
        if (
            len(set(prediction.source_refs)) != len(prediction.source_refs)
            or set(prediction.source_refs) != actual_refs
        ):
            raise ValueError("prediction_source_refs_mismatch")

    def to_outcomes(
        self, machine: Prediction, gold: GoldRecord, policy: object
    ) -> tuple[Outcome, ...]:
        self.validate_gold(gold)
        if machine.item_id != gold.item_id:
            raise ValueError("outcome_identity_mismatch")
        located = False
        if machine.status == "ok":
            self.validate_prediction(machine)
            label = IncidentLabel.model_validate(gold.label_payload.payload)
            selection = EvidenceSelection.model_validate(machine.domain_payload)
            located = any(
                witness.source_id == label.source_id
                and witness.source_ref == gold.source_ref
                and witness.generation_id is not None
                and row.omitted is None
                and label.start_line <= row.line_no <= label.end_line
                and label.trace_marker in row.text
                for witness in self._evidence._select(
                    machine.item_id, machine.method, selection.evidence_refs
                )
                for row in witness.rows
            )
        return (
            Outcome.model_validate_json(
                canonical_bytes(
                    {
                        "item_id": gold.item_id,
                        "group_id": gold.group_id,
                        "dataset": gold.dataset,
                        "split": gold.split,
                        "method": machine.method,
                        "field": None,
                        "class": None,
                        "eligibility": "eligible",
                        "status": machine.status,
                        "correct": None if machine.status == "not_run" else located,
                        "predicted": None if machine.status == "not_run" else located,
                        "expected": True,
                        "human_touched_prediction": machine.human_effective_output is not None,
                        "evidence_origin": machine.origin,
                        "issues": (
                            []
                            if located
                            else ["not_run"]
                            if machine.status == "not_run"
                            else ["incident_not_located"]
                        ),
                        "ledger_refs": machine.ledger_refs,
                    }
                )
            ),
        )

    def metric_specs(self) -> tuple[MetricSpec, ...]:
        return (
            MetricSpec(
                metric="incident_located",
                statistic_version="evalkit2492628_accuracy_v1",
                population="as_frozen",
                denominator_policy="all_frozen_incidents",
                zero_denominator_reason="no_eligible_incidents",
                averaging="none",
            ),
        )

    def public_projection_policy(self) -> PublicProjectionPolicy:
        return PublicProjectionPolicy.model_validate_json(
            canonical_bytes(
                {
                    "mode": "aggregate_only",
                    "allowed_dimensions": ["method", "split", "metric"],
                    "allowed_value_sets": {
                        "method": list(METHODS),
                        "split": ["dev", "heldout"],
                        "metric": ["incident_located"],
                    },
                    "allowed_numeric_metrics": [
                        "value",
                        "numerator",
                        "denominator",
                        "corpus_N",
                        "eligible_N",
                        "answered_N",
                        "error_N",
                        "abstention_N",
                        "stale_N",
                    ],
                    "synthetic_example_refs": [],
                }
            )
        )
