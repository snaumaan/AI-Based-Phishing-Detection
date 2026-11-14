"""Transparent prototype-based few-shot demonstration using class centroids."""
from collections import Counter
from .features import extract_features, FEATURE_NAMES


def vectorize(input_type: str, text: str) -> list[float]:
    f = extract_features(input_type, text)
    return [f[name] for name in FEATURE_NAMES]


def few_shot_predict(input_type: str, query: str, support_examples: list[tuple[str, int]]) -> dict:
    """Nearest-centroid prototype classifier over normalized handcrafted features."""
    if len(support_examples) < 2 or {label for _, label in support_examples} != {0, 1}:
        raise ValueError("Provide at least two support examples, including both classes 0 (legitimate) and 1 (phishing).")

    support = [(vectorize(input_type, text), int(label)) for text, label in support_examples]
    query_vec = vectorize(input_type, query)

    # Dynamic scaling: compute maximum across support set (or 1.0) so all features contribute fairly
    n_features = len(FEATURE_NAMES)
    max_vals = [
        max(1.0, max(abs(vec[i]) for vec, _ in support))
        for i in range(n_features)
    ]

    def normalized(v):
        return [min(1.0, max(-1.0, v[i] / max_vals[i])) for i in range(n_features)]

    q = normalized(query_vec)
    prototypes = {}
    for label in (0, 1):
        vectors = [normalized(v) for v, y in support if y == label]
        prototypes[label] = [
            sum(row[i] for row in vectors) / len(vectors)
            for i in range(n_features)
        ]

    # Euclidean distance to each prototype
    distances = {
        label: sum((a - b) ** 2 for a, b in zip(q, proto)) ** 0.5
        for label, proto in prototypes.items()
    }
    pred = min(distances, key=distances.get)

    return {
        "label": "Phishing-like" if pred == 1 else "Likely legitimate",
        "class_id": pred,
        "distances": {k: round(float(v), 4) for k, v in distances.items()},
        "support_counts": dict(Counter(y for _, y in support)),
        "note": "Prototype-based nearest centroid demonstration. Distances represent feature-space proximity to class prototypes."
    }
