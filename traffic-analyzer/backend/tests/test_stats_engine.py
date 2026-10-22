"""Tests for the statistics engine: protocol layers, hosts, filters and the summary."""

from __future__ import annotations

import pytest

from app.models.packet import NormalizedPacket
from app.services.stats import (
    application_protocol_counts,
    build_summary,
    conversation_counts,
    filter_packets,
    host_counts,
    protocol_counts,
    size_distribution,
    timeline_buckets,
)


def packet(**overrides) -> NormalizedPacket:
    data = {
        "frame_number": 1,
        "timestamp": "2026-10-21T18:00:00.000000Z",
        "timestamp_epoch": 1_772_000_000.0,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 51000,
        "destination_port": 80,
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "captured_frame_length": 100,
        "ip_packet_length": 80,
    }
    data.update(overrides)
    return NormalizedPacket(**data)


def sample_packets() -> list[NormalizedPacket]:
    return [
        packet(frame_number=1, application_protocol="HTTP", http_method="GET", captured_frame_length=100),
        packet(
            frame_number=2,
            timestamp="2026-10-21T18:00:01.000000Z",
            timestamp_epoch=1_772_000_001.0,
            application_protocol="HTTP",
            http_status_code=200,
            source_ip="10.0.0.2",
            destination_ip="10.0.0.1",
            source_port=80,
            destination_port=51000,
            captured_frame_length=200,
        ),
        packet(
            frame_number=3,
            timestamp="2026-10-21T18:00:02.000000Z",
            timestamp_epoch=1_772_000_002.0,
            application_protocol="TLS",
            transport_protocol="TCP",
            is_encrypted=True,
            tls_version="TLSv1.3",
            source_port=51001,
            destination_port=443,
            captured_frame_length=1400,
        ),
        packet(
            frame_number=4,
            timestamp="2026-10-21T18:00:03.000000Z",
            timestamp_epoch=1_772_000_003.0,
            application_protocol="DNS",
            transport_protocol="UDP",
            source_port=51002,
            destination_port=53,
            captured_frame_length=60,
        ),
    ]


class TestProtocolLayers:
    def test_transport_distribution_sums_to_the_packet_count(self):
        packets = sample_packets()
        counts = protocol_counts(packets)
        assert sum(item.packets for item in counts) == len(packets)
        assert {item.protocol for item in counts} == {"TCP", "UDP"}

    def test_application_distribution_sums_to_the_packet_count(self):
        packets = sample_packets()
        counts = application_protocol_counts(packets)
        assert sum(item.packets for item in counts) == len(packets)
        assert {item.protocol for item in counts} == {"HTTP", "TLS", "DNS"}

    def test_the_two_layers_are_not_the_same(self):
        packets = sample_packets()
        transport = {item.protocol: item.packets for item in protocol_counts(packets)}
        application = {item.protocol: item.packets for item in application_protocol_counts(packets)}
        assert transport != application

    def test_bytes_are_counted_on_the_wire(self):
        counts = {item.protocol: item.bytes for item in application_protocol_counts(sample_packets())}
        assert counts["HTTP"] == 300
        assert counts["TLS"] == 1400
        assert counts["DNS"] == 60

    def test_percentages_are_rounded(self):
        for item in application_protocol_counts(sample_packets()):
            assert round(item.percentage, 2) == item.percentage
            assert 0 <= item.percentage <= 100


class TestHostCounts:
    def test_bytes_are_split_by_direction(self):
        hosts = {host.ip: host for host in host_counts(sample_packets())}
        # 10.0.0.1 sends the HTTP request (100), the TLS record (1400) and the DNS
        # query (60); it receives the HTTP response (200).
        assert hosts["10.0.0.1"].bytes_sent == 100 + 1400 + 60
        assert hosts["10.0.0.1"].bytes_received == 200
        assert hosts["10.0.0.1"].total_bytes == 100 + 200 + 1400 + 60

    def test_protocols_are_listed_per_host(self):
        hosts = {host.ip: host for host in host_counts(sample_packets())}
        assert "HTTP" in hosts["10.0.0.1"].protocols
        assert "TLS" in hosts["10.0.0.1"].protocols


class TestConversations:
    def test_conversations_group_both_directions(self):
        conversations = conversation_counts(sample_packets())
        assert conversations
        top = conversations[0]
        assert {top.source_ip, top.destination_ip} == {"10.0.0.1", "10.0.0.2"}


class TestFilters:
    def test_filter_by_application_protocol(self):
        result = filter_packets(sample_packets(), protocol="HTTP")
        assert len(result) == 2
        assert all(p.application_protocol == "HTTP" for p in result)

    def test_filter_by_transport(self):
        result = filter_packets(sample_packets(), transport="UDP")
        assert len(result) == 1
        assert result[0].application_protocol == "DNS"

    def test_free_text_search(self):
        # every packet mentions 10.0.0.1 as source or destination
        assert len(filter_packets(sample_packets(), q="10.0.0.1")) == 4
        assert len(filter_packets(sample_packets(), q="10.0.0.9")) == 0
        assert len(filter_packets(sample_packets(), q="tls")) == 1

    def test_port_and_address_filters(self):
        assert len(filter_packets(sample_packets(), src_port=51000)) == 1
        assert len(filter_packets(sample_packets(), dst_ip="10.0.0.1")) == 1

    def test_byte_range_filter(self):
        assert len(filter_packets(sample_packets(), min_bytes=200)) == 2
        assert len(filter_packets(sample_packets(), max_bytes=100)) == 2

    def test_encrypted_filter(self):
        assert len(filter_packets(sample_packets(), encrypted=True)) == 1
        assert len(filter_packets(sample_packets(), encrypted=False)) == 3

    def test_http_filters(self):
        assert len(filter_packets(sample_packets(), method="GET")) == 1
        assert len(filter_packets(sample_packets(), status_code=200)) == 1

    def test_ordering(self):
        descending = filter_packets(sample_packets(), order_by="captured_frame_length", order_dir="desc")
        assert descending[0].captured_frame_length == 1400
        ascending = filter_packets(sample_packets(), order_by="captured_frame_length", order_dir="asc")
        assert ascending[0].captured_frame_length == 60

    def test_unknown_filter_values_are_ignored(self):
        assert len(filter_packets(sample_packets(), protocol="", q=None, min_bytes=None)) == 4


class TestTimelineAndSizeDistribution:
    def test_timeline_covers_the_whole_capture(self):
        packets = [
            packet(
                frame_number=index + 1,
                timestamp_epoch=1_772_000_000.0 + index,
                captured_frame_length=100,
            )
            for index in range(10)
        ]
        buckets = timeline_buckets(packets)
        assert sum(bucket.packets for bucket in buckets) == 10
        assert sum(bucket.bytes for bucket in buckets) == 1000
        assert buckets[0].timestamp.startswith("2026-")

    def test_timeline_of_an_empty_capture_is_empty(self):
        assert timeline_buckets([]) == []

    def test_timeline_never_exceeds_the_bucket_limit(self):
        packets = [
            packet(frame_number=index + 1, timestamp_epoch=1_772_000_000.0 + index * 60)
            for index in range(500)
        ]
        buckets = timeline_buckets(packets)
        assert 0 < len(buckets) <= 120
        assert sum(bucket.packets for bucket in buckets) == 500

    def test_size_distribution_counts_every_packet(self):
        packets = [
            packet(frame_number=1, captured_frame_length=40),
            packet(frame_number=2, captured_frame_length=100),
            packet(frame_number=3, captured_frame_length=1500),
            packet(frame_number=4, captured_frame_length=20000),
        ]
        buckets = size_distribution(packets)
        assert sum(bucket.packets for bucket in buckets) == 4
        by_label = {bucket.label: bucket for bucket in buckets}
        assert by_label["0-63"].packets == 1
        assert by_label["64-127"].packets == 1
        assert by_label["1500-3999"].packets == 1
        assert by_label["9000+"].packets == 1
        assert by_label["9000+"].max_bytes is None

    def test_summary_carries_the_chart_aggregates(self):
        summary = build_summary(
            analysis_id="abc",
            source_file="sample.pcap",
            source_kind="pcap",
            packets=sample_packets(),
            warnings=[],
        )
        assert sum(bucket.packets for bucket in summary.timeline) == 4
        assert sum(bucket.packets for bucket in summary.size_distribution) == 4
        assert len(summary.size_distribution) == 9


class TestSummary:
    def test_summary_totals(self):
        summary = build_summary(
            analysis_id="abc",
            source_file="sample.pcap",
            source_kind="pcap",
            packets=sample_packets(),
            warnings=["a warning"],
        )
        assert summary.packet_count == 4
        assert summary.total_bytes == 100 + 200 + 1400 + 60
        assert summary.duration_seconds == pytest.approx(3.0)
        assert summary.encrypted_packet_count == 1
        assert summary.http_request_count == 1
        assert summary.http_response_count == 1
        assert summary.unique_hosts == 2
        assert summary.warnings == ["a warning"]
        assert summary.http_status_counts[0].status_code == 200

    def test_summary_of_an_empty_capture(self):
        summary = build_summary(
            analysis_id="abc",
            source_file="empty.pcap",
            source_kind="pcap",
            packets=[],
            warnings=[],
        )
        assert summary.packet_count == 0
        assert summary.total_bytes == 0
        assert summary.duration_seconds == 0.0
        assert summary.protocol_counts == []
