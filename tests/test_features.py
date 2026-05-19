import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features import FEATURE_COLUMNS, FeatureBucket, _bucket_to_row, _window_key

def test_window_key_groups_by_seconds():
    assert _window_key(1_700_000_000, 60) == _window_key(1_700_000_005, 60)
    assert _window_key(1_700_000_000, 60) + 1 == _window_key(1_700_000_060, 60)

def test_bucket_to_row_has_all_feature_columns():
    b = FeatureBucket(packets=100, bytes_total=15000,
                      dst_ips={"1.1.1.1","2.2.2.2"}, dst_ports={443,80},
                      packet_sizes=[100,200,300],
                      tcp_count=80, udp_count=20, dns_count=5,
                      outbound=70, inbound=30)
    row = _bucket_to_row("192.168.1.50", 28_333_333, b, 60)
    for col in FEATURE_COLUMNS:
        assert col in row
    assert row["tcp_ratio"] == 0.8

def test_bucket_to_row_handles_empty_buckets():
    row = _bucket_to_row("10.0.0.1", 0, FeatureBucket(), 60)
    assert row["packet_count"] == 0
    assert row["avg_packet_size"] == 0.0

def test_feature_columns_stable():
    expected = {"packet_count","byte_count","unique_dst_ips","unique_dst_ports",
                "avg_packet_size","tcp_ratio","udp_ratio","dns_count","outbound_inbound_ratio"}
    assert set(FEATURE_COLUMNS) == expected
