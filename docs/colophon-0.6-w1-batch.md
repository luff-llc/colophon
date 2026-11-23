# Colophon 0.6 W1 batch record reads

Proposed text for Colophon 0.6. This proposal is open for review.

## Exchange

`POST {base}/records/batch` reads an ordered list of records from a home. The
request has no query, carries `Content-Type: application/json` and
`Content-Length`, and has a JSON body of the form `{"paths":[…]}`. The body
MUST be at most 64 KiB. The list MUST contain 1–256 unique record paths
relative to `{base}/records/` and valid under the home's store layout.

This POST is a read exception to the call purpose rule in
[0.5 §14](../spec/colophon-0.5.md#14-exchange). The home MUST require one
`colophon.home.read` call for the entire batch, including public history and
heads. The audience is `{base}` and the call's signed `args` are
`{"method":"POST","path":"/records/batch","body":"<lowercase hex SHA-256 of the raw request body>"}`.
The home verifies the call under §12.3 and applies the replay rules in §12.4.
The batch purpose is always `colophon.home.read`. A `colophon.history.read`
call is refused, so recover-only and suspended controllers must use single GET
to read members-only history.

A batch MUST NOT reach further than single-record reads. Besides the conditions
on the batch call's own `args`, the conditions of the member's terms and of
every link in the call MUST hold, for every requested path, against the `args`
a single `GET {base}/records/<path>` would carry
(`{"method":"GET","path":"/records/<path>","body":"<SHA-256 of the empty string>"}`).
If any path is out of scope the home refuses the entire batch with 403
`refused:outOfScope` at §12.3 step 7, before reserving the call or reading
storage.

## Whole-request failure

An unappointed home MUST answer 404 before checking authorization or parsing the
body. At an appointed home, invalid JSON or paths return 400, a missing call
returns 401 with `WWW-Authenticate: Colophon`, and a refused call returns 403
with `{"result":"<§1 result>"}`. Missing `Content-Length` returns 411, a body
over 64 KiB returns 413, and an unsupported content type returns 415. A rate or
replay-share limit returns 429 with `Retry-After`.

A stopped home returns 503 with `{"result":"unavailable"}` for a well-formed
batch carrying a call. A single GET may still serve public history at a stopped
home. If a record the home would return fails its storage integrity check, or is
indexed but missing or unreadable, the entire batch fails with 500, naming no
path. Whole-request errors carry no per-item results.
After a 500, the batch call remains spent. Clients can use single-record GETs
to fetch unaffected paths.

## Successful response

The home returns HTTP 200 and `{"records":[…],"truncated":bool}` with
`Cache-Control: no-store, no-transform`. Each item contains `path` and a
numeric `status`. Items appear in the request's order.

| Status | Meaning and additional fields |
| --- | --- |
| 200 | Record found. `etag` is the quoted lowercase hex SHA-256 of the record and `bytes` is standard base64 of the raw bytes. |
| 404 | Record absent. |
| 413 | The record alone would exceed the batch response budget. `etag` is the quoted SHA-256 and `size` is the raw byte count. The client may fetch it with single GET. |
| 503 | The home's own head is due and cannot be produced. The item contains no head bytes. |

The entire encoded JSON response, including base64 and framing, MUST fit within
4 MiB. If the next item cannot fit in the remaining budget, the home returns the
prefix it has assembled and sets `truncated` to `true`. An individual 413
item counts as a returned path. When `truncated` is `true`, the client MUST
use a fresh call bound to the new request body to ask for the unreturned suffix.
