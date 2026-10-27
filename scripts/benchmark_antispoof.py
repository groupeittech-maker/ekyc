"""Anti-spoofing (liveness) benchmark: FAR/FRR on a labeled local dataset.

Expected dataset layout:

    dataset/
    ├── live/     <- genuine live captures (real faces)
    │   ├── 001.jpg
    │   └── ...
    └── spoof/    <- presentation attacks (screens, prints, replays)
        ├── 001.jpg
        └── ...

The spoof FAR (spoofs accepted as live) is the safety-critical figure; the
live FRR (live users rejected) is the UX figure.

Usage:
    python -m scripts.benchmark_antispoof --dataset-dir ./var/benchmark_liveness
    python -m scripts.benchmark_antispoof --dataset-dir ./var/benchmark_liveness --threshold 0.6
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from app.engines.providers.inhouse import InHouseFaceProvider


def _images(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(
        p for p in folder.iterdir() if p.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Anti-spoof benchmark")
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    live = _images(args.dataset_dir / "live")
    spoof = _images(args.dataset_dir / "spoof")
    if not live or not spoof:
        print(
            f"Need both live/ and spoof/ images under {args.dataset_dir} "
            f"(live={len(live)}, spoof={len(spoof)})",
            file=sys.stderr,
        )
        return 1

    provider = InHouseFaceProvider()
    live_scores, spoof_scores = [], []
    failed = 0
    for path in live:
        try:
            live_scores.append(provider.liveness(path.read_bytes()).score)
        except Exception:
            failed += 1
            live_scores.append(float("nan"))
    for path in spoof:
        try:
            spoof_scores.append(provider.liveness(path.read_bytes()).score)
        except Exception:
            failed += 1
            spoof_scores.append(float("nan"))

    live_arr = np.array(live_scores)
    spoof_arr = np.array(spoof_scores)
    t = args.threshold
    result = {
        "provider": provider.name,
        "threshold": t,
        "live_images": len(live),
        "spoof_images": len(spoof),
        "failed_images": failed,
        # FRR: share of genuine captures refused
        "live_frr": round(float(np.mean(live_arr < t)), 4),
        # FAR: share of spoofs accepted — the safety-critical figure
        "spoof_far": round(float(np.mean(spoof_arr >= t)), 4),
        "mean_live_score": round(float(np.nanmean(live_arr)), 4),
        "mean_spoof_score": round(float(np.nanmean(spoof_arr)), 4),
        "note": "spoof_far must be ~0 before production; rerun after any threshold/model change",
    }

    print(json.dumps(result, indent=2))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2))
        print(f"Saved to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
