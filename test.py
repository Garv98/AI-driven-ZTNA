# File: quick_test.py

from app import estimate_network_latency, extract_flow_features_with_directions

# Your last three capture files
capture_files = [
    "captures/Abhi_20250427_190821.pcapng",
    "captures/Abhi_20250427_191549.pcapng",
    "captures/Abhi_20250427_191659.pcapng"
]

for pcap in capture_files:
    print(f"\n=== Testing file: {pcap} ===")

    latency = estimate_network_latency(pcap)
    print(f"Estimated Latency (ms): {latency}")

    features = extract_flow_features_with_directions(pcap)
    for key, value in features.items():
        print(f"{key}: {value}")



