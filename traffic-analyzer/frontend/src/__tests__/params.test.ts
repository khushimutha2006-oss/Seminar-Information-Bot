import { describe, expect, it } from 'vitest';
import { buildExportQuery, buildPacketQuery, EMPTY_FILTERS, localDateTimeToIso } from '../api/params';
import type { PacketFilters } from '../api/params';

function filters(overrides: Partial<PacketFilters>): PacketFilters {
  return { ...EMPTY_FILTERS, ...overrides };
}

describe('buildPacketQuery', () => {
  it('omits every empty filter so the backend keeps its own defaults', () => {
    const params = new URLSearchParams(buildPacketQuery(EMPTY_FILTERS, { limit: 100, offset: 0 }));
    expect(params.get('limit')).toBe('100');
    expect(params.get('offset')).toBe('0');
    for (const field of [
      'q',
      'protocol',
      'transport',
      'src_ip',
      'dst_ip',
      'src_port',
      'dst_port',
      'method',
      'status_code',
      'min_bytes',
      'max_bytes',
      'start',
      'end',
      'encrypted',
    ]) {
      expect(params.get(field)).toBeNull();
    }
  });

  it('sends the documented filter parameters', () => {
    const query = buildPacketQuery(
      filters({
        q: 'example.com',
        protocol: 'HTTP',
        transport: 'TCP',
        src_ip: '10.0.0.1',
        dst_ip: '10.0.0.2',
        src_port: '1234',
        dst_port: '443',
        method: 'GET',
        status_code: '200',
        min_bytes: '60',
        max_bytes: '1500',
        encrypted: 'true',
        order_by: 'timestamp',
        order_dir: 'desc',
      }),
    );
    const params = new URLSearchParams(query);
    expect(params.get('q')).toBe('example.com');
    expect(params.get('protocol')).toBe('HTTP');
    expect(params.get('transport')).toBe('TCP');
    expect(params.get('src_ip')).toBe('10.0.0.1');
    expect(params.get('dst_ip')).toBe('10.0.0.2');
    expect(params.get('src_port')).toBe('1234');
    expect(params.get('dst_port')).toBe('443');
    expect(params.get('method')).toBe('GET');
    expect(params.get('status_code')).toBe('200');
    expect(params.get('min_bytes')).toBe('60');
    expect(params.get('max_bytes')).toBe('1500');
    expect(params.get('encrypted')).toBe('true');
    expect(params.get('order_by')).toBe('timestamp');
    expect(params.get('order_dir')).toBe('desc');
  });

  it('drops values that are not valid integers instead of sending garbage', () => {
    const query = buildPacketQuery(filters({ src_port: 'abc', status_code: '' }));
    const params = new URLSearchParams(query);
    expect(params.get('src_port')).toBeNull();
    expect(params.get('status_code')).toBeNull();
  });

  it('never sends an empty encrypted value', () => {
    expect(buildPacketQuery(filters({ encrypted: '' }))).not.toContain('encrypted');
  });

  it('always pages the packet list', () => {
    const query = buildPacketQuery(EMPTY_FILTERS, { limit: 100, offset: 200 });
    const params = new URLSearchParams(query);
    expect(params.get('limit')).toBe('100');
    expect(params.get('offset')).toBe('200');
  });

  it('omits the page window for exports', () => {
    const query = buildExportQuery(filters({ q: 'http' }));
    const params = new URLSearchParams(query);
    expect(params.get('q')).toBe('http');
    expect(params.get('limit')).toBeNull();
    expect(params.get('offset')).toBeNull();
  });
});

describe('localDateTimeToIso', () => {
  it('converts a local datetime value to an ISO-8601 UTC timestamp', () => {
    const iso = localDateTimeToIso('2026-10-21T18:30');
    expect(iso).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it('returns null for an empty or unusable value', () => {
    expect(localDateTimeToIso('')).toBeNull();
    expect(localDateTimeToIso('not-a-date')).toBeNull();
  });
});
