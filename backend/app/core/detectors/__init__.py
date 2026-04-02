from app.core.detectors.base import BaseDetector, VulnerabilityFound
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.xss import XSSDetector
from app.core.detectors.command_injection import CommandInjectionDetector
from app.core.detectors.secrets import HardcodedSecretsDetector
from app.core.detectors.weak_crypto import WeakCryptoDetector
from app.core.detectors.deserialization import InsecureDeserializationDetector
from app.core.detectors.unsafe_eval import UnsafeEvalDetector
from app.core.detectors.path_traversal import PathTraversalDetector
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.detectors.exception_handling import ExceptionHandlingDetector
from app.core.detectors.taint_flow import TaintFlowDetector


def get_detectors_for_language(language: str = "python") -> list[BaseDetector]:
    """
    Return detector instances for a language.

    Today, full AST detectors are Python-only; taint detector receives the
    requested language so future parser expansion can reuse it directly.
    """
    detectors: list[BaseDetector] = [
        SQLInjectionDetector(),
        XSSDetector(),
        CommandInjectionDetector(),
        HardcodedSecretsDetector(),
        WeakCryptoDetector(),
        InsecureDeserializationDetector(),
        UnsafeEvalDetector(),
        PathTraversalDetector(),
        SupplyChainDetector(),
        ExceptionHandlingDetector(),
    ]
    detectors.append(TaintFlowDetector(language=language))
    return detectors


ALL_PYTHON_DETECTORS: list[BaseDetector] = get_detectors_for_language("python")

__all__ = [
    "BaseDetector",
    "VulnerabilityFound",
    "ALL_PYTHON_DETECTORS",
    "get_detectors_for_language",
]
