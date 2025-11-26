def heuristic_large_packet(features):
    return features.get("packet_size", 0) > 1400

def heuristic_high_bytes(features):
    return features.get("byte_rate", 0) > 100000

HEURISTIC_RULES = [
    heuristic_large_packet,
    heuristic_high_bytes
]