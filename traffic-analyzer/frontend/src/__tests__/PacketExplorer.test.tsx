// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketExplorer } from '../components/PacketExplorer';
import { EMPTY_FILTERS } from '../api/params';
import type { NormalizedPacket, PacketPage } from '../api/types';

function packet(overrides: Partial<NormalizedPacket> = {}): NormalizedPacket {
  return {
    frame_number: 1,
    timestamp: '2026-10-21T18:23:27.755302Z',
    timestamp_epoch: 1_767_000_207.755302,
    source_ip: '10.0.0.1',
    destination_ip: '10.0.0.2',
    source_port: 51234,
    destination_port: 443,
    transport_protocol: 'TCP',
    application_protocol: 'TLS',
    captured_frame_length: 74,
    ip_packet_length: 60,
    tcp_flags: '0x0018',
    tcp_stream_id: 0,
    http_method: null,
    http_status_code: null,
    tls_version: null,
    server_name: null,
    inter_packet_interval_seconds: null,
    is_encrypted: true,
    protocols: ['eth', 'ip', 'tcp', 'tls'],
    info: null,
    source_file: 'sample.pcap',
    ip_version: 4,
    direction_hint: 'unknown',
    ...overrides,
  };
}

function renderExplorer(page: PacketPage | null, hasAnalysis = true) {
  return render(
    <PacketExplorer
      filters={EMPTY_FILTERS}
      onApplyFilters={vi.fn()}
      page={page}
      error={null}
      loading={false}
      limit={100}
      offset={0}
      onLimitChange={vi.fn()}
      onOffsetChange={vi.fn()}
      hasAnalysis={hasAnalysis}
    />,
  );
}

afterEach(() => {
  cleanup();
});

describe('PacketExplorer', () => {
  it('shows the em dash for every value the capture did not provide', () => {
    const page: PacketPage = {
      items: [packet({ transport_protocol: null, application_protocol: null })],
      total: 1,
      limit: 100,
      offset: 0,
    };
    renderExplorer(page);

    const row = screen.getAllByRole('row')[1];
    const cells = row?.querySelectorAll('td') ?? [];
    // transport, application protocol, http method, http status, tls version, server name
    expect(cells[3]?.textContent).toBe('—');
    expect(cells[4]?.textContent).toBe('—');
    expect(cells[6]?.textContent).toBe('—');
    expect(cells[7]?.textContent).toBe('—');
    expect(cells[8]?.textContent).toBe('—');
    expect(cells[9]?.textContent).toBe('—');
    expect(row?.textContent).not.toContain('null');
  });

  it('keeps a real zero length instead of hiding it behind a dash', () => {
    const page: PacketPage = {
      items: [packet({ captured_frame_length: 0, source_port: 0, destination_port: 0 })],
      total: 1,
      limit: 100,
      offset: 0,
    };
    renderExplorer(page);

    const row = screen.getAllByRole('row')[1];
    const cells = row?.querySelectorAll('td') ?? [];
    expect(cells[5]?.textContent).toBe('0');
    expect(cells[1]?.textContent).toBe('10.0.0.1:0');
  });

  it('shows the total row count from the API, not the number of rendered rows', () => {
    const page: PacketPage = {
      items: [packet(), packet({ frame_number: 2 })],
      total: 1204,
      limit: 100,
      offset: 0,
    };
    renderExplorer(page);

    expect(screen.getAllByRole('row')).toHaveLength(3); // header + 2 rendered rows
    expect(screen.getByText(/1,204/)).toBeDefined();
  });

  it('states that an empty analysis contains 0 packets instead of showing an error', () => {
    const page: PacketPage = { items: [], total: 0, limit: 100, offset: 0 };
    renderExplorer(page);

    expect(screen.getByText('0 packets')).toBeDefined();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('states that no analysis is loaded yet', () => {
    renderExplorer(null, false);
    expect(screen.getAllByText('No analysis loaded yet').length).toBeGreaterThan(0);
  });

  it('disables the previous button on the first page and enables next when more rows exist', () => {
    const page: PacketPage = {
      items: [packet()],
      total: 1204,
      limit: 100,
      offset: 0,
    };
    renderExplorer(page);

    expect(screen.getByRole('button', { name: /previous/i })).toHaveProperty('disabled', true);
    expect(screen.getByRole('button', { name: /next/i })).toHaveProperty('disabled', false);
  });
});
