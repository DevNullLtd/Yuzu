#pragma once

// certificates_pem_fixtures.hpp -- real captured PEM certificate fixtures
// shared between test_certificates_x509.cpp and test_certificates_linux_store.cpp,
// so the two suites do not hand-copy the same bytes out of sync with each
// other. Moved out of test_certificates_x509.cpp's anonymous namespace,
// where these two constants originated; see that file for the rest of its
// fixture set (only these two are shared today).
//
// Existing fixtures, preserved byte-for-byte from test_certificates_x509.cpp --
// see each constant's own provenance comment: kRealSystemDefaultCertPem is a
// genuine capture, kExpiredCertPem is openssl-generated synthetic (both
// provenance comments say which).

// ── Real capture: System.keychain, first block ──────────────────────────────
//
// Captured 2026-08-14T19:06:27Z host=Alexs-MacBook-Air.local macos=26.5.2,
// rc=0, by: sh -c "security find-certificate -a -p
// /Library/Keychains/System.keychain | head -c 500000" -- this is the FIRST PEM
// block of that capture, a genuine macOS system-identity certificate,
// byte-for-byte as captured. Re-capturing on another host yields a DIFFERENT
// certificate (the system identity is per-machine), so this block, not the
// command, is the fixture.
//
// Verified against it (verified host OpenSSL 3.6.2):
//   $ openssl x509 -noout -subject -issuer -serial -fingerprint -sha1 -ext keyUsage -in cert1.pem
//   subject=CN=com.apple.systemdefault, O=System Identity
//   issuer=CN=com.apple.systemdefault, O=System Identity
//   serial=5AB45DC6
//   sha1 Fingerprint=E3:63:C8:FA:8D:5C:C5:08:74:56:54:26:69:F6:C6:33:26:75:87:F2
//   X509v3 Key Usage:
//       Digital Signature, Key Encipherment, Data Encipherment
//   $ openssl x509 -noout -startdate -enddate -in cert1.pem
//   notBefore=Oct  8 21:28:39 2022 GMT
//   notAfter=Oct  3 21:28:39 2042 GMT
//
// Thumbprint (colons stripped, uppercase): E363C8FA8D5CC5087456542669F6C633267587F2
inline constexpr const char* kRealSystemDefaultCertPem = R"(-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIEWrRdxjANBgkqhkiG9w0BAQsFADA8MSAwHgYDVQQDDBdj
b20uYXBwbGUuc3lzdGVtZGVmYXVsdDEYMBYGA1UECgwPU3lzdGVtIElkZW50aXR5
MB4XDTIyMTAwODIxMjgzOVoXDTQyMTAwMzIxMjgzOVowPDEgMB4GA1UEAwwXY29t
LmFwcGxlLnN5c3RlbWRlZmF1bHQxGDAWBgNVBAoMD1N5c3RlbSBJZGVudGl0eTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKgl58SsQSJ+XhqHn/XgwSHK
YM3M5nhVkSl/xKiz1jvKYBtvWjvlSDTQy5mQ7hRk7Qj/2EJSDiIl9AhD0qPU2M8c
IdL6pn7mfJVUVEK/unhKvr5nJEfdXKIhc8DontIPLDEW1xUbxVGkA4zeozIAjo8l
DirhbhmZ1LLtuNzfZub295UQp7iOizPYol8hwWqtVRZeG2ouqN/8vlk+TUQlRI21
UR8eUufjH3uDEFSJkf55eIxQz4HD6eKzKBazilKiUE/kzUUaVqDNd/W0Z0ERDLic
6cK+TEQsdmv0zunklKKM8dMu3TADoj8orQdgjWkcNLlKiREsCWsOI8xAqPJL9lkC
AwEAAaNJMEcwCwYDVR0PBAQDAgSwMCIGA1UdEQQbMBmCF2NvbS5hcHBsZS5zeXN0
ZW1kZWZhdWx0MBQGA1UdJQQNMAsGCSqGSIb3Y2QEBDANBgkqhkiG9w0BAQsFAAOC
AQEAVGS+UbSwKPq38g/VSlBEK45MpSuB8zRF36u3jAMLWhd5iAENEygNsHMFnqyy
gk+6lM0x8K2hA2hZvPFycP5ZUQyUqiXR1234mJ7brQgIrl2wJxX6Sz7FtkYpGg2Z
jQxT6pxDxqw2RJbIz4Kox+TTFvV/Sx/4AmdJN9OVZfkDYlYTiVkC9g3kUBUrzSeO
qgTqw72AadP8OqSJykLIF9xs29w5FVr36Jh370i58w+qy3KU7o6gwWWhfVVBjjBV
lLRWW0KknzZSXMWXM78/qPe8IDBQElKg+qAceQD2zB91por6QerRkdXmtl0CtsuP
vp7XnhPLblSLFY/trPrbGXu7Cw==
-----END CERTIFICATE-----
)";

// ── Synthetic: expired cert (notAfter in the past) ───────────────────────────
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -subj '/CN=expired-cert' \
//     -not_before 20200101000000Z -not_after 20210101000000Z -sha256 -out expired.pem
// $ openssl x509 -noout -startdate -enddate -in expired.pem
//   notBefore=Jan  1 00:00:00 2020 GMT
//   notAfter=Jan  1 00:00:00 2021 GMT
inline constexpr const char* kExpiredCertPem = R"(-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUX8xgpbv8KmYlEwrbELUGcKyR9/UwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMZXhwaXJlZC1jZXJ0MB4XDTIwMDEwMTAwMDAwMFoXDTIx
MDEwMTAwMDAwMFowFzEVMBMGA1UEAwwMZXhwaXJlZC1jZXJ0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy1v4DkKI0Z9BtOLs2+4ji7IH0MT7U8LXzcdz
80j7drbdmflwf2zKyhqDFfCE52FdU/ANPl3lHuWCuc/UVD6DVqOwkwO4ekvvtUVQ
SH6mbLA4BSCbp3gmyqDgaEVfNsAM7DHMTsqLfbDejTilnjzzHeHcuNbsxMH7T6Qy
aIIaMUOHygElarat5eMx19CVDBhy0JrAVMaBku4ceSWP5ipVOqzlhcLgBBfT8p+/
KdzcKGyjYgvipgudfJXZpqk6axBh6xssQsIkuqcXmDkQz77giQUXKlFIB0KlaCoX
A6juPS9XpyWqKQ2iRG5nnqL9VMoilnIskQdnNbL2UVe+lbZdSwIDAQABo1MwUTAd
BgNVHQ4EFgQU4t2+TPyG/2UIM9FZyNJN+IvCWTQwHwYDVR0jBBgwFoAU4t2+TPyG
/2UIM9FZyNJN+IvCWTQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAXU1ZWlOCFz+ELy52lpYHQPwSMh71WlCecB+jstMZ+o09QflAVRKdwNVa0hKd
nihJSegSoUmC/7RjW/zfwvsO8EMlEeTW06pHkSmOtsbLGlCRVDHJYrsXOlY3nswi
ZypRgumWMByvdI17Ut5out0FitkOL/oprTYygH+An2tiwY5SDW2pkwFNkjGaUm97
fx+rQf0UN4NIjHL0BGNaj6EhyrtmHlPDKy3GaVOwS1bfuXDY8RJJY5D3k/B1eWI7
0m2/xMhhdltL3KzXWsGs5uExMvkNPEH2RC5Y41h4Q2A/gK2LD2j01X7htmZ6fHAH
o1O+mvv2u0O0bWUxE6ID/fdNuQ==
-----END CERTIFICATE-----
)";
