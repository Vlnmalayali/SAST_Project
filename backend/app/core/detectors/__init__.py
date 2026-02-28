from app.core.detectors.base import BaseDetector, VulnerabilityFound
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.xss import XSSDetector
from app.core.detectors.command_injection import CommandInjectionDetector
from app.core.detectors.secrets import HardcodedSecretsDetector
from app.core.detectors.weak_crypto import WeakCryptoDetector
from app.core.detectors.deserialization import InsecureDeserializationDetector
from app.core.detectors.unsafe_eval import UnsafeEvalDetector
from app.core.detectors.path_traversal import PathTraversalDetector

ALL_PYTHON_DETECTORS: list[BaseDetector] = [
    SQLInjectionDetector(),
    XSSDetector(),
    CommandInjectionDetector(),
    HardcodedSecretsDetector(),
    WeakCryptoDetector(),
    InsecureDeserializationDetector(),
    UnsafeEvalDetector(),
    PathTraversalDetector(),
]

__all__ = [
    "BaseDetector",
    "VulnerabilityFound",
    "ALL_PYTHON_DETECTORS",
]
