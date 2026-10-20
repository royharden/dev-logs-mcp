"""In-memory S1 evaluation orchestration over canonical evalkit contracts.

The caller owns source acquisition, permission, durable heldout history and hard
process limits. This module loads no corpus, log, provider or arbitrary plugin.
File digests identify installed source bytes, not in-memory runtime attestation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ..shared.evalkit.corpus import FrozenCorpusError, validate_records
from ..shared.evalkit.identity import canonical_bytes
from ..shared.evalkit.models import (
    GoldRecord,
    Manifest,
    MetricRow,
    PublicMethodInput,
    PublicProjectionPolicy,
    SourceRef,
)
from ..shared.evalkit.reporting import metric_row, not_measured_row, public_aggregate
from ..shared.evalkit.runner import (
    Comparison,
    HeldoutAdmission,
    HeldoutHistory,
    MethodConfig,
    SourceView,
    compare,
)
from ..shared.evalkit.statistics import accuracy
from ..shared.mcpkit.conformance.cases import Observation
from . import domain, methods
from .domain import METHODS, EvidenceStore, IncidentAdapter
from .methods import VERSION, CallMetrics, FixedMethod, RecordingClient

Transport = Callable[[str, dict], Observation]
TransportFactory = Callable[[str, str, str], Transport]


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def implementation_digest() -> str:
    """Bind the app scorer and fixed methods, without touching source log files."""
    return digest(
        {
            name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for name, module in (("domain", domain), ("methods", methods))
        }
    )


def method_config_hashes(
    implementation_sha256: str, *, max_calls: int = 64, max_seconds: float = 30.0
) -> dict[str, str]:
    """The fixed methods remain the single owner of their configuration identity."""
    return {
        name: FixedMethod(
            name, None, implementation_sha256, max_calls=max_calls, max_seconds=max_seconds
        ).config_sha256
        for name in METHODS
    }


def input_bundle_digest(records, public_inputs, sources) -> str:
    """Pin parsed scorer/public/source bindings; never a replacement for a file hash."""
    return digest(
        {
            "records": [row.model_dump(mode="json") for row in records],
            "public_inputs": {
                key: row.model_dump(mode="json") for key, row in public_inputs.items()
            },
            "sources": {key: row.model_dump(mode="json") for key, row in sources.items()},
        }
    )


@dataclass(frozen=True)
class Admission:
    """Caller-approved pins; computing these values is not permission to execute."""

    candidate_commit: str
    manifest_sha256: str
    implementation_sha256: str
    input_bundle_sha256: str
    method_config_sha256: Mapping[str, str]


@dataclass(frozen=True)
class EvaluationResult:
    comparison: Comparison
    metric_rows: tuple[MetricRow, ...]
    # Private receipt accounting, including failures that produce no valid evidence.
    call_metrics: dict[str, dict[str, CallMetrics]]
    admission: Admission
    publication_policy: PublicProjectionPolicy

    def public_aggregates(self) -> tuple[dict[str, object], ...]:
        return tuple(public_aggregate(row, self.publication_policy) for row in self.metric_rows)


def evaluate(
    *,
    admission: Admission,
    observed_candidate_commit: str,
    manifest: Manifest,
    split: str,
    records: tuple[GoldRecord, ...],
    public_inputs: Mapping[str, PublicMethodInput],
    sources: Mapping[str, SourceRef],
    source_views: Mapping[str, SourceView],
    transport_factory: TransportFactory | None = None,
    execute: bool = False,
    max_calls: int = 64,
    max_seconds: float = 30.0,
    heldout_admission: HeldoutAdmission | None = None,
    heldout_history: HeldoutHistory | None = None,
) -> EvaluationResult:
    """Compare all three fixed methods against one frozen split.

    Default is explicit not-run, with no transport construction. Executing a
    supplied transport requires separate caller authority. SourceView is a
    caller assertion, not a source hash measurement performed here. A transport
    factory receives only public IDs and never scorer records or evidence stores.
    Heldout admission and exposure history are enforced by canonical compare().
    """
    if type(execute) is not bool or (execute and transport_factory is None):
        raise FrozenCorpusError("explicit_transport_execution_required")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", admission.candidate_commit)
        or admission.candidate_commit != observed_candidate_commit
        or admission.manifest_sha256 != digest(manifest.model_dump(mode="json"))
        or admission.implementation_sha256 != implementation_digest()
        or admission.input_bundle_sha256 != input_bundle_digest(records, public_inputs, sources)
    ):
        raise FrozenCorpusError("controller_admission_changed")
    configs = method_config_hashes(
        admission.implementation_sha256, max_calls=max_calls, max_seconds=max_seconds
    )
    if dict(admission.method_config_sha256) != configs:
        raise FrozenCorpusError("controller_method_config_changed")
    # Snapshot mutable wire payloads before invoking any caller-supplied code.
    manifest = Manifest.model_validate_json(canonical_bytes(manifest.model_dump(mode="json")))
    records = tuple(
        GoldRecord.model_validate_json(canonical_bytes(record.model_dump(mode="json")))
        for record in records
    )
    expected = tuple(record.item_id for record in records)
    if not records or len({record.dataset for record in records}) != 1:
        raise FrozenCorpusError("one_nonempty_dataset_required")
    if set(public_inputs) != set(expected) or set(source_views) != set(expected):
        raise FrozenCorpusError("controller_case_bindings_changed")
    views = {}
    for item_id, view in source_views.items():
        if not isinstance(view, SourceView) or view.status not in (
            "available",
            "stale",
            "unavailable",
        ):
            raise FrozenCorpusError("controller_source_view_invalid")
        views[item_id] = SourceView(
            view.status, view.input_sha256, json.loads(canonical_bytes(view.public_payload))
        )
    evidence = EvidenceStore(dict(sources))
    adapter = IncidentAdapter(public_inputs, evidence)
    if manifest.publication_policy != adapter.public_projection_policy():
        raise FrozenCorpusError("controller_publication_policy_changed")
    validate_records(records, manifest, split, adapter)
    if (
        heldout_admission is not None
        and heldout_admission.candidate_commit != observed_candidate_commit
    ):
        raise FrozenCorpusError("controller_heldout_candidate_changed")
    # Fail all malformed available views before any method is dispatched. A
    # changed source hash is instead retained as a stale, fixed-denominator miss.
    for record in records:
        view = views[record.item_id]
        if view.status == "available" and view.input_sha256 == record.input_sha256:
            adapter.to_public_input(record, view)

    def client_factory(item_id: str, method: str, source_id: str) -> RecordingClient:
        transport = None

        def dispatch(tool: str, arguments: dict) -> Observation:
            nonlocal transport
            # Construct inside RecordingClient.call so construction failures are
            # still attempted calls, with unknown read costs and no fake response.
            if transport is None:
                transport = transport_factory(item_id, method, source_id)
            return transport(tool, arguments)

        return RecordingClient(
            item_id,
            method,
            source_id,
            dispatch,
            evidence,
            max_calls=max_calls,
            max_seconds=max_seconds,
        )

    runners = {
        name: FixedMethod(
            name,
            client_factory,
            admission.implementation_sha256,
            max_calls=max_calls,
            max_seconds=max_seconds,
        )
        for name in METHODS
    }
    comparison = compare(
        {
            name: MethodConfig(VERSION, configs[name], "synthetic", runner if execute else None)
            for name, runner in runners.items()
        },
        manifest,
        split,
        records,
        adapter,
        None,
        lambda record: views[record.item_id],
        heldout_admission=heldout_admission,
        heldout_history=heldout_history,
    )
    spec = adapter.metric_specs()[0]
    rows = tuple(
        metric_row(
            result.outcomes,
            expected,
            spec,
            accuracy,
            method=name,
            dataset_alias=records[0].dataset,
            split=split,
            config_ref=configs[name],
        )
        if result.status == "executed"
        else not_measured_row(
            expected,
            expected,
            spec,
            method=name,
            dataset_alias=records[0].dataset,
            split=split,
            config_ref=configs[name],
        )
        for name, result in comparison.methods.items()
    )
    return EvaluationResult(
        comparison,
        rows,
        {name: dict(runner.metrics_by_item) for name, runner in runners.items()},
        Admission(
            admission.candidate_commit,
            admission.manifest_sha256,
            admission.implementation_sha256,
            admission.input_bundle_sha256,
            dict(configs),
        ),
        manifest.publication_policy,
    )
