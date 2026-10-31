"""Рекомендация по алерту: вердикт TP/FP, уверенность, эскалация и конкретные действия."""

from .engine import Assessment, Factor, assess, guess_category, specific_remediation

__all__ = ["Assessment", "Factor", "assess", "guess_category", "specific_remediation"]
