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


def _face_files(dataset_dir: Path) -> dict[str, list[Path]]:
    by_id: dict[str, list[Path]] = {}
    for person in sorted(dataset_dir.iterdir()):
        if not person.is_dir():
            continue
        images = sorted(
            p for p in person.iterdir() if p.suffix.lower() in {".jpg", ".jpeg", ".png"}
        )
        if images:
            by_id[person.name] = images
    return by_id


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
    args = parser.parse_args(argv)

    random.seed(args.seed)
    by_id = _face_files(args.dataset_dir)
    if len(by_id) < 2:
        print(
            f"Need at least 2 identities in {args.dataset_dir}; found {len(by_id)}", file=sys.stderr
        )
        return 1

    genuine, impostor = _build_pairs(by_id)
    if not genuine:
        print("Need at least one identity with 2+ images to build genuine pairs.", file=sys.stderr)
        return 1

    provider = InHouseFaceProvider()
    genuine_scores = [_score_pair(provider, _load_image(a), _load_image(b)) for a, b in genuine]
    impostor_scores = [_score_pair(provider, _load_image(a), _load_image(b)) for a, b in impostor]

    result = _metrics(genuine_scores, impostor_scores, args.threshold)
    print(json.dumps(result, indent=2))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
