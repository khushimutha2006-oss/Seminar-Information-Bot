import { describe, expect, it } from 'vitest';
import {
  DASH,
  dash,
  formatBytes,
  formatDuration,
  formatEndpoint,
  formatFullTimestamp,
  formatNumber,
  formatPercent,
  formatTimestamp,
} from '../lib/format';

describe('dash', () => {
  it('renders an em dash for missing values', () => {
    expect(dash(null)).toBe(DASH);
    expect(dash(undefined)).toBe(DASH);
    expect(dash('')).toBe(DASH);
    expect(dash('   ')).toBe(DASH);
  });

  it('never turns a real zero into a dash', () => {
    expect(dash(0)).toBe('0');
    expect(dash(0.0)).toBe('0');
  });

  it('keeps real values', () => {
    expect(dash('GET')).toBe('GET');
    expect(dash(200)).toBe('200');
  });
});

describe('formatBytes', () => {
  it('formats byte counts', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(981234)).toBe('958 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
  });

  it('shows a dash for a missing byte count', () => {
    expect(formatBytes(null)).toBe(DASH);
    expect(formatBytes(undefined)).toBe(DASH);
  });
});

describe('formatDuration', () => {
  it('formats sub-second, second and minute durations', () => {
    expect(formatDuration(0.25)).toBe('250 ms');
    expect(formatDuration(1.5)).toBe('1.500 s');
    expect(formatDuration(90)).toBe('1 min 30.0 s');
    expect(formatDuration(3725)).toBe('1 h 02 min');
  });
});

describe('formatEndpoint', () => {
  it('combines ip and port', () => {
    expect(formatEndpoint('10.0.0.1', 443)).toBe('10.0.0.1:443');
  });

  it('keeps a missing part visible instead of inventing one', () => {
    expect(formatEndpoint(null, null)).toBe(DASH);
    expect(formatEndpoint('10.0.0.1', null)).toBe('10.0.0.1');
    expect(formatEndpoint(null, 53)).toBe(':53');
  });
});

describe('formatTimestamp', () => {
  it('shows the UTC time of day and keeps the full value available', () => {
    expect(formatTimestamp('2026-10-21T18:23:27.755302Z')).toBe('18:23:27.755302');
    expect(formatFullTimestamp('2026-10-21T18:23:27.755302Z')).toBe(
      '2026-10-21 18:23:27.755302 UTC',
    );
  });

  it('shows a dash for a missing timestamp', () => {
    expect(formatTimestamp(null)).toBe(DASH);
    expect(formatFullTimestamp(null)).toBe(DASH);
  });
});

describe('number formatting', () => {
  it('formats counts and percentages', () => {
    expect(formatNumber(1204)).toBe('1,204');
    expect(formatNumber(0)).toBe('0');
    expect(formatNumber(null)).toBe(DASH);
    expect(formatPercent(24.92)).toBe('24.92%');
    expect(formatPercent(null)).toBe(DASH);
  });
});
