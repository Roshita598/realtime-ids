def rule_syn_flood(features):
    return features.get("tcp_flags") == 0x02  # SYN

def rule_fin_scan(features):
    return features.get("tcp_flags") == 0x01  # FIN

def rule_xmas_scan(features):
    return features.get("tcp_flags") == 0x29  # FIN+PSH+URG

def rule_null_scan(features):
    return features.get("tcp_flags") == 0x00  # No flags

def rule_high_rate(features):
    return features.get("packet_rate", 0) > 200

SIGNATURE_RULES = [
    rule_syn_flood,
    rule_fin_scan,
    rule_xmas_scan,
    rule_null_scan,
    rule_high_rate
]