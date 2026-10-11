# task 14 — TLS socket handler (FPC `sslsockets` compatible)

Layer 4. Dependencies: 12 (TLS 1.2), optionally 13 (TLS 1.3).

## Goal

Wrap the TLS client (task 12/13) in a socket handler compatible with the
`TSSLSocketHandler` interface from FPC `sslsockets`, so that a consumer (for
example an HTTP client built on `fphttpclient`) can use it instead of
`opensslsockets`, without depending on the system OpenSSL. Changes in the
consuming layer stay minimal.

## File

`src/tls.tlssocket.pas`

## What to implement

- `TTLSSocketHandler` — implements the same interface as
  `TOpenSSLSocketHandler` (see `opensslsockets.pp`):
  - `Connect: Boolean` — TCP connection + TLS handshake (client).
  - `Send(Buffer, Count)`, `Recv(Buffer, Count)` — encrypted read/write
    (with handling of WANT_READ/WANT_WRITE-like states).
  - `Shutdown`, `Close`, `BytesAvailable`.
  - `DoVerifyCert` — certificate verification (task 11) + SNI.
  - `CreateCertGenerator` — stub (server mode is out of scope).
- Registration as the default handler (analogous to `initialization` in
  `opensslsockets`): `TSSLSocketHandler.SetDefaultHandlerClass(...)`.
- Configuration: trust store (CA file), verification mode (strict by
  default), choice of TLS 1.2/1.3.
- `ITLSTransport` (from task 12) implemented on top of `TInetSocket`.

## Acceptance criteria

- `TInetSocket.Create(Host, Port, TTLSSocketHandler)` + `Connect`
  establishes a TLS connection with a real server.
- `Send`/`Recv` exchange an HTTP request/response correctly.
- Invalid certificate → `Connect`/`DoVerifyCert` return False with a reason.
- Compatible with `TSSLSocketHandler.GetDefaultHandler`, so a consumer that
  already uses FPC's SSL sockets needs no code changes.
- Tests — `tests/test_tlssocket.pas` (against a mock/real server).

## References

- `opensslsockets.pp` (interface reference, `TOpenSSLSocketHandler`),
  `sslsockets.pp` (`TSSLSocketHandler`, `TSSLSocket`), `ssockets.pp`
  (`TInetSocket`, `TSocketHandler`).
