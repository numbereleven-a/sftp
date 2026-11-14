# Third-party components

This distribution includes statically linked components:

- libssh2, Copyright the libssh2 contributors, BSD-3-Clause license. See `thirdparty/libssh2/COPYING` in the source distribution.
- Mbed TLS, Copyright the Mbed TLS contributors, Apache-2.0 OR GPL-2.0-or-later. This distribution uses the Apache-2.0 option. See `thirdparty/mbedtls/LICENSE` in the source distribution.
- Argon2, Copyright the Argon2 contributors, CC0-1.0 OR Apache-2.0. This distribution uses the Apache-2.0 option. See `licenses/Argon2-LICENSE.txt` in the source distribution.

Complete component license texts are included in the `licenses` directory of the binary distribution. The plugin's MIT license is in `LICENSE.md`.

The bundled libssh2 1.11.1 includes security backports for CVE-2025-15661,
CVE-2026-7598, CVE-2026-55199, CVE-2026-55200, CVE-2026-58050,
CVE-2026-58051, CVE-2026-66032, CVE-2026-66034, and CVE-2026-66035.
The SFTP reply parser also preserves the request-ID field when decoding STATUS
replies. OpenSSL-specific changes are not used by the mbedTLS build.
