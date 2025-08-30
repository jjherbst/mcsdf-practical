from scipy.stats import entropy as scipy_entropy  # type: ignore

def calculate_entropy(data: bytes) -> float:
    """ calculate shannon entropy using SciPy. """
    if not data:
        return 0.0

    # Build histogram of byte values [0..255]
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    total = len(data)
    if total == 0:
        return 0.0

    # Convert non-zero counts to probabilities
    probs = [c / total for c in counts if c]

    # Use SciPy's entropy with base-2 (bits per byte)
    return round(float(scipy_entropy(probs, base=2)), 2)
