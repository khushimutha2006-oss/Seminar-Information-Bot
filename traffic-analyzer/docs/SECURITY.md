# Security Notes

The traffic analyzer is a **local analysis tool**. It is designed to run on a laptop or
a lab machine, next to the captures it analyses. It is not hardened for the public
internet, and this document says so plainly rather than claiming protections that do
not exist.

## 1. Threat model

| Asset | Where it lives | Who can reach it |
|---|---|---|
| Uploaded capture files | `backend/data/uploads/` | anyone with filesystem access |
| Analyses (packet metadata) | `backend/data/analyses/<id>/` | anyone with filesystem access |
| The API (port 8000) | localhost by default | anyone who can open a TCP connection |
| The TShark / dumpcap child process | the server user's privileges | the API, through `/api/capture/start` |

What is **not** stored: raw packet payloads are never persisted. The store keeps
normalised metadata only (addresses, ports, lengths, timestamps, protocol labels, HTTP
methods and status codes, TLS versions and SNI host names). Even so, that metadata
describes who talked to whom, so the data directory should be treated as sensitive.

## 2. Controls that are in place

* **Upload size limit** — `config.MAX_UPLOAD_BYTES` (256 MB by default) is checked
  before the file is parsed. Over-sized uploads are rejected with `413`.
* **Filename sanitisation** — an upload name containing `..`, `/` or `\` is rejected
  with `400`. The stored file name is reduced to its basename, so an upload can never
  be written outside `config.UPLOADS_DIR`.
* **No shell execution of user input** — every subprocess is started with an argument
  list (`subprocess.run([...])` / `subprocess.Popen([...])`); `shell=True` is never
  used anywhere in the backend. Capture filters are additionally rejected when they
  contain shell metacharacters (`; & | $ \`` and newlines).
* **Interface validation** — `POST /api/capture/start` checks the requested interface
  against the interfaces the host actually offers and answers `400` for an unknown
  one, so the value cannot be used to smuggle extra arguments into the capture tool.
* **CORS allow-list** — only the origins in `config.CORS_ORIGINS` are accepted
  (default: `localhost:5173` and `localhost:4173`). No credentials are allowed.
* **No stack traces in responses** — every error is rendered as
  `{"error": {"code", "message", "detail"}}`; internal exception types are not
  disclosed and the message never contains a traceback.
* **No secrets in the repository** — the backend contains no credentials and makes no
  outbound HTTP requests; the analysis is entirely local.
* **Bounded subprocess runs** — TShark calls have a timeout
  (`config.TSHARK_TIMEOUT_SECONDS`), and a capture process is terminated (then killed)
  when the capture is stopped or the application exits.

## 3. Known limitations — what is *not* implemented

* **No authentication and no authorisation.** Anyone who can reach the port can upload
  captures and read every analysis. Run it on `127.0.0.1` (the default) and do not
  expose it to a network you do not control.
* **No transport security.** The API speaks plain HTTP; there is no TLS and no
  authentication, so it must not be put behind a reverse proxy that forwards it to an
  untrusted network without adding authentication of its own.
* **No rate limiting and no audit log.** A client can upload repeatedly and there is
  no record of who did what.
* **The capture tool runs with the server user's privileges.** Started as root, the
  TShark child process is root. Capture permissions come from `CAP_NET_RAW` on
  `dumpcap`; when they are missing, live capture fails with `503 unavailable` and
  offline analysis keeps working.
* **The built-in reader parses untrusted binary files.** Malformed captures are
  rejected with a clear error and the process does not crash, but the parser has not
  been fuzzed.
* **Analyses on disk are not encrypted** and are not deleted automatically.
* **Packet metadata is not scrubbed.** An analysis can contain internal addresses and
  SNI host names, so a shared analysis directory leaks information about the network
  that was captured.

## 4. Manual verification checklist

Run these after any change to the ingestion path:

```bash
# 1. Path traversal in a file name is rejected.
curl -s -X POST http://127.0.0.1:8000/api/analysis/upload \
     -F 'file=@/etc/passwd;filename=../../etc/passwd'      # expect 400

# 2. An unsupported file type is rejected.
curl -s -X POST http://127.0.0.1:8000/api/analysis/upload \
     -F 'file=@/bin/sh;filename=tool.sh'                    # expect 415

# 3. A corrupt capture is rejected without a stack trace.
curl -s -X POST http://127.0.0.1:8000/api/analysis/upload \
     -F 'file=@/dev/urandom;filename=random.pcap'           # expect 400, no "Traceback"

# 4. Shell metacharacters in a capture filter are rejected.
curl -s -X POST http://127.0.0.1:8000/api/capture/start \
     -H 'Content-Type: application/json' \
     -d '{"interface":"lo","filter":"tcp port 80; rm -rf /"}'   # expect 400

# 5. An unknown interface is rejected.
curl -s -X POST http://127.0.0.1:8000/api/capture/start \
     -H 'Content-Type: application/json' \
     -d '{"interface":"definitely-not-an-interface"}'      # expect 400

# 6. Nothing was written outside the uploads directory.
find backend/data/uploads -name '..*' -o -name '*passwd*'   # expect no output
```

The automated equivalents live in `backend/tests/test_security.py`.
