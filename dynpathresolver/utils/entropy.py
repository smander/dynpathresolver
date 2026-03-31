"""Shannon entropy calculation utility."""

import math


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data.

    Returns a value between 0.0 (uniform) and 8.0 (maximum entropy).
    """
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy
