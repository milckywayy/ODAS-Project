import math
from collections import Counter


def entropy(text):
    if not text:
        return 0.0

    char_count = Counter(text)
    length = len(text)

    entropy_value = 0.0
    for char, count in char_count.items():
        probability = count / length
        entropy_value -= probability * math.log2(probability)

    return entropy_value
