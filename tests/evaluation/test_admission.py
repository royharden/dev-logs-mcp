"""Handwritten temp inputs only; no campaign, native log reader or provider."""

import hashlib
from dataclasses import replace

import pytest

from dev_logs_mcp.evaluation.admission import (
    CorpusAdmission,
    SourceBinding,
    binding_digest,
    evaluate_from_corpus,
    public_input_digest,
)
from dev_logs_mcp.evaluation.controller import (
    Admission,
    digest,
    implementation_digest,
    input_bundle_digest,
    method_config_hashes,
)
from dev_logs_mcp.evaluation.domain import EvidenceStore, IncidentAdapter
from dev_logs_mcp.shared.evalkit.corpus import FrozenCorpusError
from dev_logs_mcp.shared.evalkit.identity import canonical_bytes, ordered_ids_digest
from dev_logs_mcp.shared.evalkit.models import (
    GoldRecord,
    Manifest,
    PinnedReference,
    PublicMethodInput,
    SourceRef,
)
from dev_logs_mcp.shared.evalkit.runner import HeldoutAdmission, HeldoutHistory


@pytest.fixture
def job(tmp_path, monkeypatch):
    """what_bug_this_catches: disjoint handwritten splits never read existing Gold."""

    def forbidden(*_args, **_kwargs):
        pytest.fail("unexpected process, network or native log reader")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("ctypes.WinDLL", forbidden, raising=False)
    monkeypatch.setattr(
        "dev_logs_mcp.shared.mcpkit.safe_path.SafePathPolicy.open_source", forbidden
    )
    declared = PinnedReference(status="available", ref="handwritten-permission", sha256="c" * 64)
    rows, publics, sources, bindings, snapshots, entries, artifacts = {}, {}, {}, {}, {}, [], []
    for split in ("dev", "heldout"):
        item, source_id = f"{split}_case", f"{split}_source"
        data = f"INFO {split} handwritten\nERROR original_{split}_trace\n".encode()
        source = SourceRef(handle=f"{split}_snapshot", sha256=hashlib.sha256(data).hexdigest())
        public = PublicMethodInput.model_validate_json(
            canonical_bytes(
                {
                    "item_id": item,
                    "input_sha256": digest([source.sha256, "operation failed"]),
                    "public_payload": {"source_id": source_id, "symptom_hint": "operation failed"},
                    "public_config_refs": [],
                }
            )
        )
        row = GoldRecord.model_validate_json(
            canonical_bytes(
                {
                    "item_id": item,
                    "dataset": "handwritten_dataset",
                    "group_id": f"{split}_group",
                    "split": split,
                    "label_version": "handwritten_v1",
                    "source_ref": source.model_dump(),
                    "input_sha256": public.input_sha256,
                    "label_source": "synthetic",
                    "label_provenance_ref": "handwritten_control",
                    "domain_kind": "log_incident/1",
                    "label_payload": {
                        "kind": "domain_labels",
                        "payload": {
                            "source_id": source_id,
                            "start_line": 2,
                            "end_line": 2,
                            "trace_marker": f"original_{split}_trace",
                        },
                    },
                }
            )
        )
        raw = canonical_bytes(row.model_dump(mode="json")) + b"\n"
        (tmp_path / f"{split}.jsonl").write_bytes(raw)
        entries.append(
            {
                "split": split,
                "items_file": f"{split}.jsonl",
                "item_count": 1,
                "ordered_item_ids": [item],
                "items_sha256": hashlib.sha256(raw).hexdigest(),
                "ordered_ids_sha256": ordered_ids_digest((item,)),
                "group_ids": [row.group_id],
            }
        )
        artifacts.append(
            {
                "namespace": source_id,
                "status": "available",
                "sha256": source.sha256,
                "count": 1,
                "member_ids": [item],
            }
        )
        rows[split], publics[split], sources[split], snapshots[split] = row, public, source, data
        bindings[split] = SourceBinding(
            source_id=source_id,
            source_ref=source,
            artifact_namespace=source_id,
            split=split,
            rights=declared,
            authority=declared,
        )
    selected_public = {publics["dev"].item_id: publics["dev"]}
    selected_sources, selected_bindings = (
        {"dev_source": sources["dev"]},
        {"dev_source": bindings["dev"]},
    )
    adapter = IncidentAdapter(selected_public, EvidenceStore(selected_sources))
    manifest = Manifest.model_validate_json(
        canonical_bytes(
            {
                "manifest_id": "handwritten_manifest",
                "parent_manifest_sha256": None,
                "split_seed": 1,
                "partition_provenance": "seeded",
                "frozen_at": "2026-01-01T00:00:00Z",
                "scorer_version": "handwritten_v1",
                "comparator_config": declared.model_dump(),
                "domain_adapter_ref": declared.model_dump(),
                "experiment_refs": {},
                "splits": entries,
                "group_split_map": {f"{split}_group": split for split in rows},
                "group_members": {f"{split}_group": [rows[split].item_id] for split in rows},
                "source_artifacts": artifacts,
                "publication_policy": adapter.public_projection_policy().model_dump(mode="json"),
                "run_history_ref": "handwritten_history",
            }
        )
    )
    implementation = implementation_digest()
    controller = Admission(
        "1" * 40,
        digest(manifest.model_dump(mode="json")),
        implementation,
        input_bundle_digest((rows["dev"],), selected_public, selected_sources),
        method_config_hashes(implementation),
    )
    return {
        "admission": CorpusAdmission(
            controller,
            "dev",
            binding_digest(selected_bindings),
            public_input_digest(selected_public),
            declared,
            declared,
        ),
        "observed_candidate_commit": "1" * 40,
        "corpus_root": tmp_path,
        "manifest": manifest,
        "public_inputs": selected_public,
        "bindings": selected_bindings,
        "source_bytes": {"dev_source": snapshots["dev"]},
        "transport_factory": lambda *_: pytest.fail("unexpected dispatch"),
    }


def repin_manifest(job, mutate):
    wire = job["manifest"].model_dump(mode="json")
    mutate(wire)
    job["manifest"] = Manifest.model_validate_json(canonical_bytes(wire))
    controller = replace(
        job["admission"].controller, manifest_sha256=digest(job["manifest"].model_dump(mode="json"))
    )
    job["admission"] = replace(job["admission"], controller=controller)


def test_valid_original_bytes_join_controller_without_dispatch(job):
    """what_bug_this_catches: verified bytes must join existing not-run semantics."""
    result = evaluate_from_corpus(**job)
    assert result.comparison.frozen_item_ids == ("dev_case",)
    assert all(row.measurement_status == "not_measured" for row in result.metric_rows)


@pytest.mark.parametrize("change", ["corpus", "source", "public", "metadata", "candidate"])
def test_changed_bindings_refused_before_dispatch(job, change):
    """what_bug_this_catches: byte and metadata pins cannot be recomputed silently."""
    if change == "corpus":
        path = job["corpus_root"] / "dev.jsonl"
        path.write_bytes(path.read_bytes() + b" ")
    elif change == "source":
        job["source_bytes"]["dev_source"] += b"changed"
    elif change == "public":
        job["public_inputs"]["dev_case"].public_payload["symptom_hint"] = "changed"
    elif change == "metadata":
        job["bindings"]["dev_source"] = job["bindings"]["dev_source"].model_copy(
            update={"artifact_namespace": "changed"}
        )
    else:
        job["observed_candidate_commit"] = "2" * 40
    with pytest.raises(FrozenCorpusError):
        evaluate_from_corpus(**job, execute=True)


@pytest.mark.parametrize("where", ["corpus_rights", "corpus_authority", "rights", "authority"])
def test_missing_declarations_refused_before_corpus_read(job, monkeypatch, where):
    """what_bug_this_catches: missing declarations cannot open private input bytes."""
    missing = PinnedReference(status="not_available", ref="missing", sha256=None)
    if where.startswith("corpus_"):
        job["admission"] = replace(job["admission"], **{where: missing})
    else:
        job["bindings"]["dev_source"] = job["bindings"]["dev_source"].model_copy(
            update={where: missing}
        )
        job["admission"] = replace(
            job["admission"], bindings_sha256=binding_digest(job["bindings"])
        )
    monkeypatch.setattr(
        "dev_logs_mcp.evaluation.admission.load_corpus", lambda *_: pytest.fail("corpus read")
    )
    with pytest.raises(FrozenCorpusError):
        evaluate_from_corpus(**job)


def test_one_split_refused(job):
    """what_bug_this_catches: DEV-only input cannot masquerade as isolated evaluation."""

    def change(wire):
        wire["splits"] = wire["splits"][:1]
        wire["group_members"].pop("heldout_group")
        wire["group_split_map"].pop("heldout_group")
        wire["source_artifacts"] = wire["source_artifacts"][:1]

    repin_manifest(job, change)
    with pytest.raises(FrozenCorpusError, match="nondegenerate"):
        evaluate_from_corpus(**job)


def test_duplicate_source_bytes_across_splits_refused(job):
    """what_bug_this_catches: aliases/groups cannot hide reused source bytes."""
    repin_manifest(
        job,
        lambda wire: wire["source_artifacts"][1].update(
            sha256=wire["source_artifacts"][0]["sha256"]
        ),
    )
    with pytest.raises(FrozenCorpusError, match="crosses_partition"):
        evaluate_from_corpus(**job)


def test_artifact_members_cannot_be_swapped(job):
    """what_bug_this_catches: checksum alone cannot attest case membership."""
    repin_manifest(
        job, lambda wire: wire["source_artifacts"][0].update(member_ids=["heldout_case"])
    )
    with pytest.raises(FrozenCorpusError):
        evaluate_from_corpus(**job)


def test_extra_snapshot_refused(job):
    """what_bug_this_catches: heldout bytes cannot enter a DEV source bundle."""
    job["source_bytes"]["heldout_source"] = b"not acquired"
    with pytest.raises(FrozenCorpusError, match="case_bindings_changed"):
        evaluate_from_corpus(**job)


def test_heldout_requires_admission_before_corpus_read(job, monkeypatch):
    """what_bug_this_catches: absent heldout admission/history cannot expose private rows."""
    job["admission"] = replace(job["admission"], split="heldout")
    monkeypatch.setattr(
        "dev_logs_mcp.evaluation.admission.load_corpus", lambda *_: pytest.fail("corpus read")
    )
    with pytest.raises(FrozenCorpusError, match="heldout_admission_required"):
        evaluate_from_corpus(**job)


def test_invalid_heldout_pins_refused_before_corpus_read(job, monkeypatch):
    """what_bug_this_catches: a non-null admission object cannot unlock heldout bytes."""
    job["admission"] = replace(job["admission"], split="heldout")
    job["heldout_admission"] = HeldoutAdmission(
        "a" * 64, "b" * 64, "c" * 64, {}, "2" * 40, "wrong_history", None
    )
    job["heldout_history"] = HeldoutHistory()
    monkeypatch.setattr(
        "dev_logs_mcp.evaluation.admission.load_corpus", lambda *_: pytest.fail("corpus read")
    )
    with pytest.raises(FrozenCorpusError, match="heldout_frozen_admission_changed"):
        evaluate_from_corpus(**job)


def test_verified_inputs_reach_existing_controller_only_after_admission(job, monkeypatch):
    """what_bug_this_catches: the new entry must hand actual parsed rows to the controller."""
    calls = []

    def capture(**kwargs):
        calls.append(kwargs)
        return "controller-result"

    monkeypatch.setattr("dev_logs_mcp.evaluation.admission.evaluate", capture)
    assert evaluate_from_corpus(**job, execute=True) == "controller-result"
    assert len(calls) == 1 and calls[0]["execute"] is True
    assert calls[0]["records"][0].item_id == "dev_case"
    assert calls[0]["sources"] == {"dev_source": job["bindings"]["dev_source"].source_ref}
    assert calls[0]["admission"] == job["admission"].controller


def test_unavailable_artifact_cannot_claim_partition_isolation(job):
    """what_bug_this_catches: unknown heldout source hashes cannot prove isolation."""
    repin_manifest(
        job, lambda wire: wire["source_artifacts"][1].update(status="unavailable", sha256=None)
    )
    with pytest.raises(FrozenCorpusError, match="source_artifact_ambiguous"):
        evaluate_from_corpus(**job)
