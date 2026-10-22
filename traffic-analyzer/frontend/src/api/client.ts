/**
 * Low-level HTTP client for the traffic analyzer API.
 *
 * Every non-2xx response is turned into an `ApiError` carrying the backend's own
 * `error.message` text, so the UI can show the real reason instead of a generic
 * "something went wrong".
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: Record<string, unknown>;

  constructor(status: number, code: string, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.detail = detail;
  }

  /** True when the backend answered but the request could not be fulfilled as asked. */
  get isHttp(): boolean {
    return this.status > 0;
  }
}

/** Base URL: empty by default (the dev server proxies /api), overridable at build time. */
const RAW_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').trim();

export const API_BASE = RAW_BASE.replace(/\/+$/, '');

export function apiUrl(path: string): string {
  const suffix = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE}${suffix}`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readErrorEnvelope(status: number, body: unknown, rawText: string): ApiError {
  let message = `The server responded with HTTP ${status}.`;
  let code = 'http_error';
  let detail: Record<string, unknown> = {};

  if (isRecord(body) && isRecord(body.error)) {
    const envelope = body.error;
    if (typeof envelope.message === 'string' && envelope.message.length > 0) {
      message = envelope.message;
    }
    if (typeof envelope.code === 'string' && envelope.code.length > 0) {
      code = envelope.code;
    }
    if (isRecord(envelope.detail)) {
      detail = envelope.detail;
    }
  } else if (rawText.trim().length > 0) {
    message = rawText.trim().slice(0, 500);
  }

  return new ApiError(status, code, message, detail);
}

async function errorFromResponse(response: Response): Promise<ApiError> {
  let text = '';
  try {
    text = await response.text();
  } catch {
    text = '';
  }
  let parsed: unknown;
  if (text) {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = undefined;
    }
  }
  return readErrorEnvelope(response.status, parsed, text);
}

/** GET/POST a JSON route and parse the JSON response. */
export async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.headers ?? {}),
      },
    });
  } catch (cause) {
    throw new ApiError(
      0,
      'network_error',
      `The API could not be reached at ${apiUrl(path)}. Is the backend running on port 8000?`,
      { cause: String(cause) },
    );
  }

  if (!response.ok) {
    throw await errorFromResponse(response);
  }

  const text = await response.text();
  if (!text) {
    throw new ApiError(response.status, 'empty_response', 'The server returned an empty response.', {});
  }
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed as T;
  } catch {
    throw new ApiError(
      response.status,
      'invalid_response',
      'The server returned a response that is not valid JSON.',
      {},
    );
  }
}

export function postJson<T>(path: string, body: unknown): Promise<T> {
  return requestJson<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export interface UploadProgress {
  loaded: number;
  total: number;
  percent: number;
}

export interface UploadResult<T> {
  data: T;
}

/**
 * POST a file as `multipart/form-data` with the field name `file`.
 *
 * Uses XMLHttpRequest because `fetch` cannot report upload progress.
 */
export function uploadFile<T>(
  path: string,
  file: File,
  onProgress: (progress: UploadProgress) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const form = new FormData();
    form.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', apiUrl(path), true);
    xhr.responseType = 'text';

    xhr.upload.onprogress = (event: ProgressEvent) => {
      if (event.lengthComputable) {
        onProgress({
          loaded: event.loaded,
          total: event.total,
          percent: Math.round((event.loaded / event.total) * 100),
        });
      }
    };

    xhr.onload = () => {
      const raw = typeof xhr.response === 'string' ? xhr.response : xhr.responseText ?? '';
      let parsed: unknown;
      if (raw) {
        try {
          parsed = JSON.parse(raw) as unknown;
        } catch {
          parsed = undefined;
        }
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        if (parsed === undefined) {
          reject(
            new ApiError(
              xhr.status,
              'invalid_response',
              'The server accepted the upload but returned an unreadable response.',
              {},
            ),
          );
          return;
        }
        resolve(parsed as T);
        return;
      }
      reject(readErrorEnvelope(xhr.status, parsed, raw));
    };

    xhr.onerror = () => {
      reject(
        new ApiError(
          0,
          'network_error',
          'The upload failed: the server could not be reached.',
          {},
        ),
      );
    };
    xhr.onabort = () => {
      reject(new ApiError(0, 'aborted', 'The upload was cancelled.', {}));
    };

    xhr.send(form);
  });
}

/** Best-effort human readable text for any thrown value. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}
