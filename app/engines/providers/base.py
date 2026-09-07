from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class OcrResult:
    fields: dict[str, Any]
    raw_text: str = ""
    confidence: float = 0.0
    provider: str = "unknown"


@dataclass
class DocumentAuthenticityResult:
    authentic: bool
    confidence: float
    signals: dict[str, Any] = field(default_factory=dict)
    provider: str = "unknown"


@dataclass
class FaceResult:
    score: float
    provider: str = "unknown"
    details: dict[str, Any] = field(default_factory=dict)


class OcrProvider(ABC):
    name = "base"

    @abstractmethod
    def extract(self, image: bytes, document_type: str) -> OcrResult: ...

    @abstractmethod
    def check_authenticity(self, image: bytes, ocr: OcrResult) -> DocumentAuthenticityResult: ...


class FaceProvider(ABC):
    name = "base"

    @abstractmethod
    def liveness(self, selfie: bytes) -> FaceResult: ...

    @abstractmethod
    def match(self, selfie: bytes, document_image: bytes) -> FaceResult: ...


class OtpSender(ABC):
    name = "base"

    @abstractmethod
    def send(self, channel: str, destination: str, code: str) -> None: ...
