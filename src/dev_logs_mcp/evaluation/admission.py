"""Explicit corpus admission over canonical evalkit and already acquired snapshots.

This is not a log reader, native filesystem adapter or source-rights authority.
The trusted caller supplies immutable source bytes and verifies permission to
read the exact corpus root/split before invoking this private scoring entry.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from ..shared.evalkit.corpus import FrozenCorpusError, load_corpus
from ..shared.evalkit.identity import canonical_bytes
from ..shared.evalkit.models import (
    Manifest,
    PinnedReference,
    PublicMethodInput,
    SourceRef,
    Split,
    Wire,
)
from ..shared.evalkit.runner import HeldoutAdmission, HeldoutHistory, SourceView
from .controller import (
    Admission,
    EvaluationResult,
    TransportFactory,
    digest,
    evaluate,
    implementation_digest,
    method_config_hashes,
)
from .domain import EvidenceStore, IncidentAdapter


class SourceBinding(Wire):
    """Caller declarations, pinned separately from the private corpus rows."""

    source_id: str
    source_ref: SourceRef
    artifact_namespace: str
    split: Split
    rights: PinnedReference
    authority: PinnedReference


@dataclass(frozen=True)
class CorpusAdmission:
    controller: Admission
    split: str
    bindings_sha256: str
    public_inputs_sha256: str
    corpus_rights: PinnedReference
    corpus_authority: PinnedReference


class _RecordedExposure(HeldoutHistory):
    """One canonical handoff for an exposure recorded before the private read.

    This is not a history store: every invocation must first obtain successful
    recording from the caller-owned history. Failure after that point still
    consumes the exposure, including a failed corpus read or controller check.
    """

    def __init__(self, history: HeldoutHistory, admission: HeldoutAdmission):
        self._pending: HeldoutAdmission | None = replace(
            admission, method_config_sha256=dict(admission.method_config_sha256)
        )
        # The callback gets its own mutable mapping, not the canonical handoff.
        history.record_exposure(
            replace(admission, method_config_sha256=dict(admission.method_config_sha256))
        )

    def record_exposure(self, admission: HeldoutAdmission) -> None:
        expected, self._pending = self._pending, None
        if expected is None or expected != admission:
            raise FrozenCorpusError("heldout_exposure_handoff_changed_or_used")


def binding_digest(bindings: Mapping[str, SourceBinding]) -> str:
    return digest({key: row.model_dump(mode="json") for key, row in bindings.items()})


def public_input_digest(public_inputs: Mapping[str, PublicMethodInput]) -> str:
    return digest({key: row.model_dump(mode="json") for key, row in public_inputs.items()})


def _declared(reference: PinnedReference) -> bool:
    return (
        isinstance(reference, PinnedReference)
        and reference.status == "available"
        and bool(reference.ref and reference.ref.strip())
        and reference.sha256 is not None
    )


def _partition(manifest: Manifest) -> dict[str, str]:
    entries = {entry.split: entry for entry in manifest.splits}
    if set(entries) != {"dev", "heldout"} or any(
        not entry.item_count or not entry.group_ids for entry in entries.values()
    ):
        raise FrozenCorpusError("admission_nondegenerate_partition_required")
    partitions = {item: entry.split for entry in manifest.splits for item in entry.ordered_item_ids}
    if len(partitions) != sum(entry.item_count for entry in manifest.splits):
        raise FrozenCorpusError("admission_partition_members_changed")
    declared = {item for members in manifest.group_members.values() for item in members}
    if declared != partitions.keys():
        raise FrozenCorpusError("admission_partition_members_changed")
    # A source artifact may not expose the same bytes to both partitions, even
    # through different namespaces or independently named near-duplicate groups.
    seen_members, hash_splits = set(), {}
    namespaces = set()
    for artifact in manifest.source_artifacts:
        if (
            artifact.namespace in namespaces
            or not artifact.member_ids
            or artifact.status != "available"
            or artifact.sha256 is None
        ):
            raise FrozenCorpusError("admission_source_artifact_ambiguous")
        namespaces.add(artifact.namespace)
        if any(item not in partitions or item in seen_members for item in artifact.member_ids):
            raise FrozenCorpusError("admission_source_members_changed")
        seen_members.update(artifact.member_ids)
        splits = {partitions[item] for item in artifact.member_ids}
        if len(splits) != 1:
            raise FrozenCorpusError("admission_source_crosses_partition")
        if artifact.sha256 is not None:
            previous = hash_splits.setdefault(artifact.sha256, splits)
            if previous != splits:
                raise FrozenCorpusError("admission_source_crosses_partition")
    if seen_members != partitions.keys():
        raise FrozenCorpusError("admission_source_members_changed")
    return partitions


def evaluate_from_corpus(
    *,
    admission: CorpusAdmission,
    observed_candidate_commit: str,
    corpus_root: Path,
    manifest: Manifest,
    public_inputs: Mapping[str, PublicMethodInput],
    bindings: Mapping[str, SourceBinding],
    source_bytes: Mapping[str, bytes],
    transport_factory: TransportFactory | None = None,
    execute: bool = False,
    max_calls: int = 64,
    max_seconds: float = 30.0,
    heldout_admission: HeldoutAdmission | None = None,
    heldout_history: HeldoutHistory | None = None,
) -> EvaluationResult:
    """Verify admitted original bytes before handing inputs to the controller.

    References declare authority/rights; their presence/hash is not independent
    proof of permission. No referenced provenance path is opened. The caller
    owns acquisition, snapshot/native provenance, hard process limits and real
    durable heldout history. Only selected-split source snapshots are accepted.
    Default execution remains not-run; this entry performs private input reads.
    """
    admission = replace(
        admission,
        controller=replace(
            admission.controller,
            method_config_sha256=dict(admission.controller.method_config_sha256),
        ),
    )
    if heldout_admission is not None:
        heldout_admission = replace(
            heldout_admission, method_config_sha256=dict(heldout_admission.method_config_sha256)
        )
    if (
        admission.split not in ("dev", "heldout")
        or not _declared(admission.corpus_rights)
        or not _declared(admission.corpus_authority)
        or admission.controller.candidate_commit != observed_candidate_commit
        or admission.controller.manifest_sha256 != digest(manifest.model_dump(mode="json"))
        or admission.bindings_sha256 != binding_digest(bindings)
        or admission.public_inputs_sha256 != public_input_digest(public_inputs)
    ):
        raise FrozenCorpusError("corpus_admission_changed")
    if admission.split == "heldout":
        if heldout_admission is None or heldout_history is None:
            raise FrozenCorpusError("heldout_admission_required")
        seal = manifest.experiment_refs.get("heldout_seal")
        dev_lock = manifest.experiment_refs.get("dev_config_lock")
        if (
            seal is None
            or dev_lock is None
            or not _declared(seal)
            or not _declared(dev_lock)
            or heldout_admission.manifest_sha256 != admission.controller.manifest_sha256
            or heldout_admission.candidate_commit != observed_candidate_commit
            or heldout_admission.independent_seal_sha256 != seal.sha256
            or heldout_admission.dev_config_sha256 != dev_lock.sha256
            or heldout_admission.method_config_sha256 != admission.controller.method_config_sha256
            or heldout_admission.history_ref != manifest.run_history_ref
        ):
            raise FrozenCorpusError("heldout_frozen_admission_changed")
        # Compare the installed owner implementation and actual runtime bounds,
        # rather than merely comparing two potentially stale caller declarations.
        implementation = implementation_digest()
        if admission.controller.implementation_sha256 != implementation:
            raise FrozenCorpusError("controller_admission_changed")
        configs = method_config_hashes(implementation, max_calls=max_calls, max_seconds=max_seconds)
        if dict(admission.controller.method_config_sha256) != configs:
            raise FrozenCorpusError("controller_method_config_changed")
    # Snapshot nested mutable wire mappings before any file read/caller callback.
    manifest = Manifest.model_validate_json(canonical_bytes(manifest.model_dump(mode="json")))
    bindings = {
        key: SourceBinding.model_validate_json(canonical_bytes(row.model_dump(mode="json")))
        for key, row in bindings.items()
    }
    public_inputs = {
        key: PublicMethodInput.model_validate_json(canonical_bytes(row.model_dump(mode="json")))
        for key, row in public_inputs.items()
    }
    partitions = _partition(manifest)
    selected = {item for item, split in partitions.items() if split == admission.split}
    if set(public_inputs) != selected or set(bindings) != set(source_bytes):
        raise FrozenCorpusError("corpus_admission_case_bindings_changed")
    sources = {}
    artifact_by_name = {row.namespace: row for row in manifest.source_artifacts}
    for source_id, binding in bindings.items():
        artifact = artifact_by_name.get(binding.artifact_namespace)
        data = source_bytes[source_id]
        if (
            source_id != binding.source_id
            or binding.split != admission.split
            or not _declared(binding.rights)
            or not _declared(binding.authority)
            or type(data) is not bytes
            or len(data) > 10 * 1024 * 1024
            or binding.source_ref.sha256 is None
            or hashlib.sha256(data).hexdigest() != binding.source_ref.sha256
            or artifact is None
            or artifact.status != "available"
            or artifact.sha256 != binding.source_ref.sha256
            or not set(artifact.member_ids) <= selected
        ):
            raise FrozenCorpusError("corpus_admission_source_changed")
        sources[source_id] = binding.source_ref
    adapter = IncidentAdapter(public_inputs, EvidenceStore(sources))
    if admission.split == "heldout":
        # Recording is the caller's authorization boundary. A rejecting,
        # reused or unimplemented history must fail before load_corpus. The
        # unchanged canonical compare consumes this one-use handoff instead
        # of recording the same exposure twice in the durable owner history.
        heldout_history = _RecordedExposure(heldout_history, heldout_admission)
    # Canonical loader owns original JSONL byte hash, bounds, wire parsing,
    # ordered IDs, group membership and domain validation. Never reseal input.
    records = load_corpus(corpus_root, manifest, admission.split, adapter)
    actual_members = {source_id: set() for source_id in sources}
    for record in records:
        source_id = public_inputs[record.item_id].public_payload["source_id"]
        actual_members[source_id].add(record.item_id)
    if (
        any(
            actual_members[source_id]
            != set(artifact_by_name[binding.artifact_namespace].member_ids)
            for source_id, binding in bindings.items()
        )
        or set().union(*actual_members.values()) != selected
    ):
        raise FrozenCorpusError("corpus_admission_source_members_changed")
    return evaluate(
        admission=admission.controller,
        observed_candidate_commit=observed_candidate_commit,
        manifest=manifest,
        split=admission.split,
        records=records,
        public_inputs=public_inputs,
        sources=sources,
        source_views={
            item: SourceView("available", row.input_sha256, row.public_payload)
            for item, row in public_inputs.items()
        },
        transport_factory=transport_factory,
        execute=execute,
        max_calls=max_calls,
        max_seconds=max_seconds,
        heldout_admission=heldout_admission,
        heldout_history=heldout_history,
    )
