import math

def calculate_entropy(data: bytes) -> float:
    """ calculate shannon entropy manually without scipy dependency. """
    if not data:
        return 0.0

    # Build histogram of byte values [0..255]
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    total = len(data)
    if total == 0:
        return 0.0

    # Calculate Shannon entropy manually
    entropy = 0.0
    for count in counts:
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return round(entropy, 2)
