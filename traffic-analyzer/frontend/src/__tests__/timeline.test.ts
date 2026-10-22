import { describe, expect, it } from 'vitest';
import { buildTimeline } from '../lib/timeline';
import type { NormalizedPacket } from '../api/types';

function packet(frame: number, epoch: number): NormalizedPacket {
  return {
    frame_number: frame,
    timestamp: new Date(epoch * 1000).toISOString(),
    timestamp_epoch: epoch,
    source_ip: '10.0.0.1',
    destination_ip: '10.0.0.2',
    source_port: 1234,
    destination_port: 80,
    transport_protocol: 'TCP',
    application_protocol: 'HTTP',
    captured_frame_length: 74,
    ip_packet_length: 60,
    tcp_flags: '0x0018',
    tcp_stream_id: 0,
    http_method: 'GET',
    http_status_code: null,
    tls_version: null,
    server_name: 'example.com',
    inter_packet_interval_seconds: null,
    is_encrypted: false,
    protocols: ['eth', 'ip', 'tcp', 'http'],
    info: 'GET / HTTP/1.1',
    source_file: 'sample.pcap',
    ip_version: 4,
    direction_hint: 'unknown',
  };
}

describe('buildTimeline', () => {
  it('returns no buckets for an empty capture', () => {
    const timeline = buildTimeline([]);
    expect(timeline.buckets).toHaveLength(0);
    expect(timeline.covered).toBe(0);
  });

  it('groups packets into time buckets', () => {
    const base = 1_700_000_000;
    const packets = [
      packet(1, base),
      packet(2, base + 1),
      packet(3, base + 2),
      packet(4, base + 40),
    ];
    const timeline = buildTimeline(packets, 30);
    expect(timeline.covered).toBe(4);
    expect(timeline.bucketSeconds).toBeGreaterThan(0);

    const total = timeline.buckets.reduce((sum, bucket) => sum + bucket.packets, 0);
    expect(total).toBe(4);
  });

  it('puts a single capture into one bucket', () => {
    const timeline = buildTimeline([packet(1, 1_700_000_000)], 30);
    expect(timeline.buckets).toHaveLength(1);
    expect(timeline.buckets[0]?.packets).toBe(1);
  });
});
