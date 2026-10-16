"""Execution-provider selection for ONNX inference (CPU/GPU auto-detection).

ONNX Runtime is the single inference engine for self-hosted models
(anti-spoofing today; YuNet/SFace run through OpenCV's DNN module which is
CPU-only unless OpenCV itself is built with CUDA).

``EKYC_GPU_ENABLED=true`` (default) means "use the best provider available":
CUDA when the ``onnxruntime-gpu`` wheel and an NVIDIA device are present,
CPU otherwise. Setting it to ``false`` pins CPU execution — useful for
reproducible benchmarks or hosts without a GPU.
"""

from __future__ import annotations

import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

_CPU_EP = "CPUExecutionProvider"

# Preference order when GPU execution is allowed.
_PREFERRED = ("CUDAExecutionProvider", _CPU_EP)


def onnx_providers() -> list[str]:
    """Execution providers to request, best first, filtered to what's installed."""
    if not settings.gpu_enabled:
        return [_CPU_EP]
    try:
        import onnxruntime as ort

        available = set(ort.get_available_providers())
    except ImportError:
        return [_CPU_EP]
    selected = [ep for ep in _PREFERRED if ep in available]
    return selected or [_CPU_EP]


def describe() -> str:
    """Human-readable summary for startup logs, e.g. ``gpu=available (CUDA)``."""
    providers = onnx_providers()
    if providers[0] == _CPU_EP:
        return "cpu"
    return f"gpu ({providers[0]})"
