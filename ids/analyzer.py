from scapy.all import IP, TCP

class TrafficAnalyzer:

    def extract_features(self, pkt):
        features = {}

        features["packet_size"] = len(pkt)

        if IP in pkt:
            features["src"] = pkt[IP].src
            features["dst"] = pkt[IP].dst

        if TCP in pkt:
            features["tcp_flags"] = int(pkt[TCP].flags)
            features["window_size"] = pkt[TCP].window
        else:
            features["tcp_flags"] = 0
            features["window_size"] = 0

        # simple placeholders (can be replaced with flow logic)
        features["flow_duration"] = 1
        features["packet_rate"] = 10
        features["byte_rate"] = 500

        return features