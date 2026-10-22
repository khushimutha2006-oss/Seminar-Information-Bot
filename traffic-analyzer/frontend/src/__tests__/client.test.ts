import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, errorMessage, requestJson } from '../api/client';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('requestJson', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns the parsed body for a 200 response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(200, { status: 'ok', contract_version: 'v1' })),
    );
    const result = await requestJson<{ status: string }>('/api/health');
    expect(result.status).toBe('ok');
  });

  it('throws the backend error message for a 404 envelope', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(404, {
          error: {
            code: 'not_found',
            message: "Analysis 'abc123' does not exist.",
            detail: { analysis_id: 'abc123' },
          },
        }),
      ),
    );

    const error = await requestJson('/api/analysis/abc123/summary').catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.message).toBe("Analysis 'abc123' does not exist.");
    expect(apiError.status).toBe(404);
    expect(apiError.code).toBe('not_found');
    expect(apiError.detail).toEqual({ analysis_id: 'abc123' });
  });

  it('keeps the 409 conflict message for an already running capture', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(409, {
          error: {
            code: 'conflict',
            message: 'A capture is already running.',
            detail: {},
          },
        }),
      ),
    );

    const error = await requestJson('/api/capture/start', { method: 'POST' }).catch(
      (caught: unknown) => caught,
    );
    expect((error as ApiError).message).toBe('A capture is already running.');
    expect((error as ApiError).status).toBe(409);
  });

  it('keeps the 503 message when the capture tool is missing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(503, {
          error: {
            code: 'unavailable',
            message: 'TShark is not installed on this host.',
            detail: {},
          },
        }),
      ),
    );

    const error = await requestJson('/api/capture/start', { method: 'POST' }).catch(
      (caught: unknown) => caught,
    );
    expect((error as ApiError).message).toBe('TShark is not installed on this host.');
    expect((error as ApiError).status).toBe(503);
  });

  it('reports an unreachable API instead of throwing a raw TypeError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );

    const error = await requestJson('/api/health').catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(0);
    expect((error as ApiError).message).toContain('/api/health');
  });
});

describe('errorMessage', () => {
  it('uses the ApiError message and never a generic fallback', () => {
    expect(errorMessage(new ApiError(400, 'invalid_request', 'Empty file.'))).toBe('Empty file.');
  });

  it('falls back to the error text of unknown values', () => {
    expect(errorMessage(new Error('boom'))).toBe('boom');
  });
});
