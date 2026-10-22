/** Client-side bucketing of packet timestamps for the timeline chart. */

import type { NormalizedPacket } from '../api/types';

export interface TimelineBucket {
  /** Axis label, UTC time of day. */
  label: string;
  /** ISO-8601 UTC start of the bucket. */
  startIso: string;
  /** Bucket length in seconds. */
  bucketSeconds: number;
  packets: number;
}

export interface Timeline {
  buckets: TimelineBucket[];
  bucketSeconds: number;
  /** Number of packets the timeline was built from. */
  covered: number;
}

function toIso(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

function toTimeLabel(epochSeconds: number): string {
  const iso = toIso(epochSeconds);
  const match = /T(\d{2}:\d{2}:\d{2})/.exec(iso);
  return match ? (match[1] ?? iso) : iso;
}

/**
 * Group packets into fixed time buckets.
 *
 * The API exposes no timeline endpoint, so the chart is built from a bounded
 * sample of the packet list. The caller reports how much of the capture the
 * sample covers.
 */
export function buildTimeline(packets: NormalizedPacket[], targetBuckets = 30): Timeline {
  if (packets.length === 0) {
    return { buckets: [], bucketSeconds: 0, covered: 0 };
  }

  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (const packet of packets) {
    const epoch = packet.timestamp_epoch;
    if (!Number.isFinite(epoch)) continue;
    if (epoch < min) min = epoch;
    if (epoch > max) max = epoch;
  }
  if (!Number.isFinite(min) || !Number.isFinite(max)) {
    return { buckets: [], bucketSeconds: 0, covered: 0 };
  }

  const span = Math.max(0, max - min);
  const bucketSeconds = span === 0 ? 1 : Math.max(1, Math.ceil(span / Math.max(1, targetBuckets)));

  const counts = new Map<number, number>();
  for (const packet of packets) {
    const epoch = packet.timestamp_epoch;
    if (!Number.isFinite(epoch)) continue;
    const index = Math.floor((epoch - min) / bucketSeconds);
    counts.set(index, (counts.get(index) ?? 0) + 1);
  }

  const bucketCount = Math.floor(span / bucketSeconds) + 1;
  const buckets: TimelineBucket[] = [];
  for (let index = 0; index < bucketCount; index += 1) {
    const start = min + index * bucketSeconds;
    buckets.push({
      label: toTimeLabel(start),
      startIso: toIso(start),
      bucketSeconds,
      packets: counts.get(index) ?? 0,
    });
  }

  return { buckets, bucketSeconds, covered: packets.length };
}
