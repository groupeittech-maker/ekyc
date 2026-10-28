"""SFace face-matching benchmark: FAR, FRR and EER on a local dataset.

Expected dataset layout (same as LFW):

    dataset/
    ├── person_a/
    │   ├── img1.jpg
    │   └── img2.jpg
    └── person_b/
        └── img1.jpg

Genuine pairs are every combination inside the same identity folder.
Impostor pairs are one image per identity from different folders.

Usage:
    python -m scripts.benchmark_sface --dataset-dir ./var/benchmark_faces
    python -m scripts.benchmark_sface --dataset-dir ./var/benchmark_faces --threshold 0.5
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import sys
from collections.abc import Sequence
from pathlib import Path

import numpy as np

from app.engines.providers.inhouse import InHouseFaceProvider


def _load_image(path: Path) -> bytes:
    return path.read_bytes()


def _face_files(dataset_dir: Path, cohort: str | None = None) -> dict[str, list[Path]]:
    """dataset/<person>/img — or with cohorts: dataset/<cohort>/<person>/img
    (cohort = capture condition: device model, lighting, camera quality)."""
    root = dataset_dir / cohort if cohort else dataset_dir
    by_id: dict[str, list[Path]] = {}
    for person in sorted(root.iterdir()):
        if not person.is_dir():
            continue
        images = sorted(
            p for p in person.iterdir() if p.suffix.lower() in {".jpg", ".jpeg", ".png"}
        )
        if images:
            by_id[person.name] = images
    return by_id


def _cohorts(dataset_dir: Path) -> list[str]:
    """Cohort directories = first-level dirs whose children are themselves
    identity dirs. Empty = flat LFW layout (single implicit cohort)."""
    out = []
    for d in sorted(dataset_dir.iterdir()):
        if d.is_dir() and any(c.is_dir() for c in d.iterdir()):
            out.append(d.name)
    return out


def _build_pairs(
    by_id: dict[str, list[Path]],
) -> tuple[list[tuple[Path, Path]], list[tuple[Path, Path]]]:
    genuine: list[tuple[Path, Path]] = []
    for paths in by_id.values():
        genuine.extend(itertools.combinations(paths, 2))

    ids = list(by_id.keys())
    impostor: list[tuple[Path, Path]] = []
    # Keep the impostor set the same size as genuine for balance, or 10k max.
    max_impostors = max(len(genuine), 10_000)
    seen = set()
    attempts = 0
    while (
        len(impostor) < min(max_impostors, len(ids) * (len(ids) - 1) // 2 * 4)
        and attempts < max_impostors * 10
    ):
        attempts += 1
        a, b = random.sample(ids, 2)
        img_a = random.choice(by_id[a])
        img_b = random.choice(by_id[b])
        key = tuple(sorted([str(img_a), str(img_b)]))
        if key not in seen:
            seen.add(key)
            impostor.append((img_a, img_b))
    return genuine, impostor


def _score_pair(provider: InHouseFaceProvider, a: bytes, b: bytes) -> float:
    return provider.match(a, b).score


def _metrics(
    genuine_scores: Sequence[float], impostor_scores: Sequence[float], threshold: float
) -> dict:
    genuine = np.array(genuine_scores)
    impostor = np.array(impostor_scores)

    far = float(np.mean(impostor >= threshold))
    frr = float(np.mean(genuine < threshold))
    tar = 1.0 - frr
    fta = float(np.isnan(genuine).sum() + np.isnan(impostor).sum()) / (len(genuine) + len(impostor))

    # EER = threshold where FAR == FRR (intersection of the two error curves).
    thresholds = np.linspace(0.0, 1.0, 1001)
    far_curve = np.array([np.mean(impostor >= t) for t in thresholds])
    frr_curve = np.array([np.mean(genuine < t) for t in thresholds])
    diff = np.abs(far_curve - frr_curve)
    eer_idx = int(np.argmin(diff))
    eer = float((far_curve[eer_idx] + frr_curve[eer_idx]) / 2)
    eer_threshold = float(thresholds[eer_idx])

    return {
        "pairs": {"genuine": len(genuine), "impostor": len(impostor)},
        "threshold": float(threshold),
        "far": round(far, 4),
        "frr": round(frr, 4),
        "tar": round(tar, 4),
        "eer": round(eer, 4),
        "eer_threshold": round(eer_threshold, 4),
        "fta": round(fta, 4),
        "mean_genuine_score": round(float(np.mean(genuine)), 4),
        "mean_impostor_score": round(float(np.mean(impostor)), 4),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SFace benchmark")
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--cohorts", action="store_true",
                        help="dataset/<cohort>/<person>/img — metrics per cohort")
    parser.add_argument("--far-target", type=float, default=None,
                        help="exit 2 if any cohort FAR exceeds this")
    parser.add_argument("--frr-target", type=float, default=None,
                        help="exit 2 if any cohort FRR exceeds this")
    args = parser.parse_args(argv)

    random.seed(args.seed)
    cohorts = _cohorts(args.dataset_dir) if args.cohorts else [None]
    provider = InHouseFaceProvider()

    report: dict = {
        "model": "SFace",
        "provider": "inhouse",
        "threshold": args.threshold,
        "seed": args.seed,
        "cohorts": {},
    }
    all_genuine: list[float] = []
    all_impostor: list[float] = []
    for cohort in cohorts:
        by_id = _face_files(args.dataset_dir, cohort)
        if len(by_id) < 2:
            continue
        genuine, impostor = _build_pairs(by_id)
        if not genuine:
            continue
        gs = [_score_pair(provider, _load_image(a), _load_image(b)) for a, b in genuine]
        is_ = [_score_pair(provider, _load_image(a), _load_image(b)) for a, b in impostor]
        m = _metrics(gs, is_, args.threshold)
        m["identities"] = len(by_id)
        report["cohorts"][cohort or "_all"] = m
        all_genuine += gs
        all_impostor += is_

    if not all_genuine:
        print("No usable pairs found — check dataset layout.", file=sys.stderr)
        return 1

    report["combined"] = _metrics(all_genuine, all_impostor, args.threshold)
    print(json.dumps(report, indent=2))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2))

    # Acceptance gates — a threshold only ships if the WORST cohort meets it.
    fails = []
    for name, m in report["cohorts"].items():
        if args.far_target is not None and m["far"] > args.far_target:
            fails.append(f"{name}: FAR {m['far']} > {args.far_target}")
        if args.frr_target is not None and m["frr"] > args.frr_target:
            fails.append(f"{name}: FRR {m['frr']} > {args.frr_target}")
    if fails:
        print("ACCEPTANCE FAILED:", *fails, sep="\n  ", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
