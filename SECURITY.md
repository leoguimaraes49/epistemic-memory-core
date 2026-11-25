# Security Policy — Epistemic Memory Core

## Supported Versions

Security fixes are maintained on the `main` branch and current release series:

| Version | Supported |
| :--- | :--- |
| `0.5.9` / `main` | Yes |
| `< 0.5.9` | No |

## Reporting a Vulnerability

Please report security issues responsibly through GitHub Security Advisories at:
https://github.com/leoguimaraes49/epistemic-memory-core/security/advisories/new

Alternatively, open an issue without disclosing sensitive personal data at:
https://github.com/leoguimaraes49/epistemic-memory-core/issues

Include reproduction steps, affected module/path, and impact assessment.

## Security Architecture & Boundaries

- **Pre-Write Workspace Authorization:** `nucleo.is_authorized_scope` validates `EMC_SYSTEM`, `EMC_VAULT`, and `EMC_AUTHORIZED_ROOTS` before creating directories or SQLite files.
- **Default-Deny MCP Content Gate:** Personal vault tools require `CEREBRO_PESSOAL_ACESSO=permitido` in the local process environment and fail closed when `estado/implantacao.lock` is present.
- **Integrity & Locking:** Controlled records are verified with raw-byte `SHA-256` digests, committed with SQLite `PRAGMA synchronous=FULL`, protected by exclusive OS file locks (`CreateFileW` on Windows; `flock` + inode/device checks on POSIX), and guarded against symlinks and Windows NTFS junctions (`IO_REPARSE_TAG_MOUNT_POINT` / `IO_REPARSE_TAG_SYMLINK`).
- **Hardened Local HTTP Servers:** `src/dashboard.py`, `apps/dossie_studio/web.py`, and `apps/http_gateway/server.py` bind exclusively to loopback (`127.0.0.1`, `localhost`, `::1`) and enforce `Host` validation (DNS Rebinding defense), `Origin`/`Sec-Fetch-Site` checks, CSRF/Bearer tokens (`hmac.compare_digest`), 64 KB body limits, strict CSP headers, unread body draining, and sliding-window rate limiting (`HTTP 429` + `Retry-After`).
- **Explicit Non-Goals:** Vault data at rest is not encrypted by the engine; rely on full-disk encryption and OS user isolation.
