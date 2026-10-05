"""Human-readable interpretation helpers for feature contribution output."""


def describe_contribution(value: float) -> str:
    if value > 0:
        return "augmente le score de la classe analysée"
    if value < 0:
        return "diminue le score de la classe analysée"
    return "a une contribution nulle dans cette explication"