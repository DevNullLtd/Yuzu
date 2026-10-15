/**
 * test_certificates_x509.cpp -- fixture vectors for certificates_x509.hpp
 * (WP-B), the pure libcrypto PEM/DER parse header that replaces the Linux
 * `openssl x509` subprocess and backs the macOS SecItem DER decode path.
 *
 * Every vector here runs against an in-memory PEM/DER string -- no
 * filesystem, no subprocess, no keychain -- because certificates_x509.hpp is
 * pure by design (BIO_new_mem_buf / d2i_X509 over caller-supplied bytes
 * only).
 *
 * Provenance for every synthetic certificate below: generated with the
 * EMPIRICALLY VERIFIED host OpenSSL 3.6.2 at
 * /opt/homebrew/opt/openssl@3/bin/openssl (macOS, 2026-08-17) -- NOT the
 * system /usr/bin/openssl, which is LibreSSL 3.3.6 on this host and was
 * never used to derive any expected string below. The exact generating
 * command and the exact
 *   openssl x509 -noout -subject -issuer -serial -fingerprint -sha1 -ext keyUsage
 * output is recorded as a comment directly above each embedded PEM. Two
 * certificates (kRealSystemDefaultCertPem, used by the single-cert and
 * thumbprint-pinning vectors) are REAL bytes trimmed from a captured
 * System.keychain read, not synthetic -- their own provenance comment records
 * the capture command/host/date/rc verbatim. The raw pre-migration capture
 * itself is a local development artifact and is deliberately NOT committed:
 * the PEM bytes embedded below ARE the committed evidence (byte-for-byte from
 * that capture), and every expected string is re-derivable from them with the
 * commands recorded here -- nothing in this file depends on a path outside the
 * repository.
 *
 * ADR-3002 PARITY RECORD (the "parity diff before spawn deletion" obligation).
 * Verified 2026-08-17 on macOS 26.5.2 arm64 against the real
 * /opt/homebrew/opt/openssl@3/bin/openssl 3.6.2 CLI, reproducing the EXACT
 * pipeline the deleted subprocess code used per field -- `-subject`/`-issuer`
 * with the leading-space strip, `-startdate`/`-enddate -dateopt iso_8601`
 * truncated to 10 characters, `-serial`, `-fingerprint -sha1` with the colons
 * removed, and `-ext keyUsage` reduced by the left-trim/skip-X509v3/skip-
 * critical/take-last-line selection -- all under LC_ALL=C, for EVERY PEM
 * vector in this file. Result: all 7 fields IDENTICAL to parse_pem_certs()
 * output on all 11 certificate vectors, zero mismatches. That comparison
 * shells out to openssl and so deliberately does NOT live in this suite (unit
 * tests here spawn no processes); re-run it out-of-tree when changing any
 * extractor in certificates_x509.hpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <certificates_x509.hpp>

#include "certificates_pem_fixtures.hpp" // kRealSystemDefaultCertPem, kExpiredCertPem (shared with test_certificates_linux_store.cpp)

#include <span>
#include <sstream>
#include <string>
#include <vector>

using yuzu::certificates_x509::parse_der_cert;
using yuzu::certificates_x509::parse_pem_certs;

namespace {

// ── Synthetic: subject with a comma AND an unescaped '+' ────────────────────
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//     -subj '/C=GB/O=Yuzu, Inc./CN=t\+e' -sha256 -out comma_plus.pem
// $ openssl x509 -noout -subject -in comma_plus.pem
//   subject=C=GB, O=Yuzu, Inc., CN=t+e
// -- exactly the architect-pinned target: the comma inside "Yuzu, Inc." is
// NOT escaped/reversed (that would be XN_FLAG_RFC2253's
// "CN=t\+e,O=Yuzu\, Inc.,C=GB"), and the '+' in "t+e" is NOT quoted (that
// would be XN_FLAG_ONELINE's `CN = "t+e"`).
constexpr const char* kCommaPlusSubjectPem = R"(-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgIUCVrzNjX6ZheAahk8BEEkdUPAHLswDQYJKoZIhvcNAQEL
BQAwMDELMAkGA1UEBhMCR0IxEzARBgNVBAoMCll1enUsIEluYy4xDDAKBgNVBAMM
A3QrZTAeFw0yNjA4MTcxMDM4MjdaFw0zNjA4MTQxMDM4MjdaMDAxCzAJBgNVBAYT
AkdCMRMwEQYDVQQKDApZdXp1LCBJbmMuMQwwCgYDVQQDDAN0K2UwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuImiabR74E4mApMCdzlLUd7/M4+o+B73Z
HGssH5Lgy1pHFGmXQNS7lvFNg1+48TEOaEzt0iPXpdxgFWmlypy7AJHNFhgH/jXN
zW9yU9rrWTK8f7eyb9fSxTVrazGzTnMnwiQqUv86/QF8WfDtlhSvNr05UECRpVvP
eGNBWBQJiDnAXbL7TI9JJYKkj6o73RQ1rNengPUiXI7Xvip1RO+Jaz7AfArSHVwv
18zOWJkqQ/ZxLUGPfjzt1ND/PC0QtdC2hAHfo/0jW4OY1x3usK6pOhUI2oQVpg5N
KpidIH9w9gCO44C8D2ha1GsRt+dPa2906jRPL1b1hgJHRnqtpOaLAgMBAAGjUzBR
MB0GA1UdDgQWBBSXkMerfPXga6pJlybmQ5hKs7JZ8DAfBgNVHSMEGDAWgBSXkMer
fPXga6pJlybmQ5hKs7JZ8DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQCV9krZtjpBxrYAGhWkrjab2hqAPDEjPChsxduuackurd/ByCv2xl8JnfTB
nmjns5DOQDuOexzj4x/aemgafjnml3oceBA174N9YmeN8dDyT7LxZmcxZKiZYvW7
ckzeYjC0WicU7DtyRcrK1oV1LampNECuizES8fs9ijhXcxnNdQDU+PL9JZXRfU8j
vZAbJ5HyCvOu9nZ3q4oR5AnUHuhkUUMU0Ohwom0eyMPemBJ1q5Gay5jHiN6vsRFY
YPCQBgQGBkqCcwlRQ7+GmJPwZgUK0gYK3pDyjqwSb1L4u0nA0fLnbjx7PejX9OlZ
+VGqO/puw81Pb1wtAHJ52dQ4Dc/A
-----END CERTIFICATE-----
)";

// ── Synthetic: multi-valued RDN (CN+O in a single RDN) ──────────────────────
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//     -subj '/C=US/CN=multi+O=RdnCo' -multivalue-rdn -sha256 -out multi_rdn.pem
// $ openssl x509 -noout -subject -in multi_rdn.pem
//   subject=C=US, CN=multi + O=RdnCo
constexpr const char* kMultiValuedRdnPem = R"(-----BEGIN CERTIFICATE-----
MIIDNzCCAh+gAwIBAgIUe3bxzKq3SPxnG/FhPoaYuBB21vcwDQYJKoZIhvcNAQEL
BQAwKzELMAkGA1UEBhMCVVMxHDAMBgNVBAMMBW11bHRpMAwGA1UECgwFUmRuQ28w
HhcNMjYwODE3MTAzODE2WhcNMzYwODE0MTAzODE2WjArMQswCQYDVQQGEwJVUzEc
MAwGA1UEAwwFbXVsdGkwDAYDVQQKDAVSZG5DbzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMNtEIU2IepbWZFW86usyeea3ivDgN5kw8fbl7PzB85/w7QV
LZOF+sN6YV/ZUi+l081RHSpQjxYNfA1PeZZOddGp5Kt4RlX5Z3YTJL3XZs6LsZvn
lxqRD3kQeuCJ0Zy5MMK5FApjEr3YMzavujEkHG7Jd5oPdsNKTMLUqh00YrLIEr59
cCHO2NFqRbF4z0NZr1V7zA6p8EOqiSqWwQ47Ex13i+IyIjeQnUuvi0T80aNMRGfd
8yWJogWeR03imM7U7Wli9TtkA9vNbe+yhWj3P4XXlYTWz9H/qe+X/NVTcCHbjt2w
Z104uEsF36jd/f1h/ntpCwsqwH+gEWhhDuM/eNsCAwEAAaNTMFEwHQYDVR0OBBYE
FL7pWFZjvzx4Vdvb2eZNZYR94NneMB8GA1UdIwQYMBaAFL7pWFZjvzx4Vdvb2eZN
ZYR94NneMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACb3RDa5
4ebFG98Cbv9AONN8Gb88sMjYWeqrkNUaZS2eqxwKn7lhg1iUb9K30l0ls8OMl9oB
UJ+96a8qI4fPPrlZX2bbSRN8bASQ2Eg3/sjrxffG9sWmFT8OPlDB/OLiOJIFKi0Y
g0vkTE392268gmNN8DSqW8hya4VxfUDIbMfjxuus8Z3/Wuc/Xm2eyqj9UCbWY458
MY2lcTOHXD64XH7MFGV16L0HL6YjvkMRNfZ8gl03jgxcGIWrd6SjlzqAgzmbD4Zf
vPYZZwzVhra2Vo+POw8praFvl7djs720ups5arL+UIiG54Zp89rgoxH+0AUlawWM
1XRfVIVKZmYDE8s=
-----END CERTIFICATE-----
)";

// ── Synthetic: UTF-8 subject ─────────────────────────────────────────────────
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//     -subj '/C=JP/O=ユズ株式会社/CN=café' -utf8 -sha256 -out utf8.pem
// $ openssl x509 -noout -subject -in utf8.pem
//   subject=C=JP, O=ユズ株式会社, CN=café
constexpr const char* kUtf8SubjectPem = R"(-----BEGIN CERTIFICATE-----
MIIDVTCCAj2gAwIBAgIUO9N9EQsW+t2QmyvuNP7wrlliW5cwDQYJKoZIhvcNAQEL
BQAwOjELMAkGA1UEBhMCSlAxGzAZBgNVBAoMEuODpuOCuuagquW8j+S8muekvjEO
MAwGA1UEAwwFY2Fmw6kwHhcNMjYwODE3MTAzODE3WhcNMzYwODE0MTAzODE3WjA6
MQswCQYDVQQGEwJKUDEbMBkGA1UECgwS44Om44K65qCq5byP5Lya56S+MQ4wDAYD
VQQDDAVjYWbDqTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANFYkJSV
+0KOwlyl/7ut/gPS+1sXnKyZjWbOoxq70/xueTZ/1qtdk5Ofxce54qOd4jsAbdpy
fzzQlYGfkFTOIn44y91VJSgAzHzFLogTrYuSbrreiXnq0BEHuZejJzsn93r7vaMq
5CzXpfrL1L53UkWYKFVmBZMeLbokJOVtUgdoAm0IF2ytGlsSjH2fPztmjr438TRK
XsBRF5nT0wUq6iSONVsM63c96XOc+yHdImJvbbGlSbDXY4YDOrtCJhwDYrpqrPjp
hOXFJw2jlY3OllBICqcLMMZjpyEtZXou8Kjn87tmHvAqwgcJZ8wy12bOokWk9s/Z
mFkJQmkOFjtpihkCAwEAAaNTMFEwHQYDVR0OBBYEFA4ITvU1/BNpkIbbSPEHeIA+
sGeAMB8GA1UdIwQYMBaAFA4ITvU1/BNpkIbbSPEHeIA+sGeAMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAITDOOGH5uxAXjchgHdXRHLlBrA+U5BG
/XA6p31BJFDMmLL/vWVh39qZYS6O53qDagvjYF1Xafqt9XUN1Ve0Mp0zQGBeLylh
1bi45BkYCByO18PICYjK4SYG1wx1iVSSC+8ruw165v1GlZccKNbBJqd5+hNYYrEy
mlmWYeoravLtBUuVbsryxrqzGIM67q0eSJ0ZW2LLSXsRakXWsede/J+HfSI9dWmW
AzyZdJQ/TXXxoVMds/hRuf+q0zHmWCzaRYYzNyIbU3r5mZjw90JKuj++pJslRBNn
577VuvdDfYQyHwSO/OFjwCyKSbKJu+2kBDJCBX5vQ+bTUd3xhsSiEVc=
-----END CERTIFICATE-----
)";

// ── Synthetic: serial requiring a DER sign-disambiguation padding byte ──────
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=leadzero' \
//     -set_serial 0x80ABCDEF -sha256 -out lead_zero_serial.pem
// $ openssl x509 -noout -serial -in lead_zero_serial.pem
//   serial=80ABCDEF
// $ openssl asn1parse -in lead_zero_serial.pem | sed -n 4p
//       10:d=3  hl=2 l=   1 prim: INTEGER           :02   <- version, not the SN
// (the serial's own INTEGER content bytes are exactly 80ABCDEF -- the DER
// encoder needs no extra 0x00 pad here since the tag+length machinery, not
// content, carries the sign; i2a_ASN1_INTEGER's rendering matches the CLI
// exactly regardless).
constexpr const char* kLeadingZeroSerialPem = R"(-----BEGIN CERTIFICATE-----
MIIC+DCCAeCgAwIBAgIFAICrze8wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwI
bGVhZHplcm8wHhcNMjYwODE3MTAzODM4WhcNMzYwODE0MTAzODM4WjATMREwDwYD
VQQDDAhsZWFkemVybzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJAV
RsFf8vkq1MRurlCaQQdaz4IlNn4rScxTnpp/LVGXyzkammv+97L534OOw+DEc0nN
EagaF5dwbLRFhSdJmTqA5A1D4y3lrwHWeY6j5kW3jRJIn3/Qzfk0SSwxcxi4JM+j
KoWEx7Ko6SLxTeFVrpUAFOEwPJOPdIy7JRJMFxOlNcE/Brvcxfwe+NOs1PrScx2u
XVzVigEWoJgX6zUN4y4aIkeCYexCcofLooKyJO+gcms+IXMLryq6FLBavKY5K6AI
tPmmMI3zdphS0zRUyV//54sEiOUSUezNCgVMiXk7WrPdowMd0msnAULKoMhWFjAW
WHfZtbX1hrNRIzoQ0EMCAwEAAaNTMFEwHQYDVR0OBBYEFO0tJiIRG+snxL07yPBT
xYVtkSWvMB8GA1UdIwQYMBaAFO0tJiIRG+snxL07yPBTxYVtkSWvMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB2S/Q7xR+J9HUVSb2j0vum8g6d5
WLTGbuePJ3XQEIGPYQm9Y7y/2EP9Eefw4lG0sAToF4fgScNomeeco/9NqiYR435f
YqOdm4lysRuNyc1l6jt0+WM4lo9iQch6UvFUecNh2DyyAxF5VII6sqj2An6aT0MK
ICH1FQRoIy5J1v0MTSekGR2ZWnw4ykBPVs8UP75i9JF6j+J3mjexm2g9olKuxdh1
Lg1OZkFTvQv7GtkrThE3Zw2DFsJOWHJW5plU/VDvrXb4yCzL3rsGv6+8mqVJNO2t
/h9wY2ey/G8xiaUQ9LqLTi9ESYpbyJpfUuEVqQvROSmBbz+SPC1CC6giA4k=
-----END CERTIFICATE-----
)";

// ── Synthetic: serial value ZERO -- the i2a_ASN1_INTEGER vs. ────────────────
// ASN1_INTEGER_to_BN+BN_bn2hex divergence pin (see certificates_x509.hpp's
// own extract_serial() comment: this is the ONE serial value the two APIs
// render differently -- i2a prints the single content byte 0x00 as "00",
// BN_bn2hex's zero-magnitude BIGNUM prints as "0").
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=serialzero' \
//     -set_serial 0 -sha256 -out serial_zero.pem
// $ openssl x509 -noout -serial -in serial_zero.pem
//   serial=00
constexpr const char* kSerialZeroPem = R"(-----BEGIN CERTIFICATE-----
MIIC+DCCAeCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApzZXJp
YWx6ZXJvMB4XDTI2MDgxNzEwMzg1N1oXDTM2MDgxNDEwMzg1N1owFTETMBEGA1UE
AwwKc2VyaWFsemVybzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJXN
XINC8ZSXOskK6dLii7LGHIAI6UkA3GhnCVuyUPrLoVxMu8MeoOzu6iDUt6Hy63S2
ICbHp69sNmHBe6Enzkl2mYmMNhsai/PWm/Q3l+gGQantzW2JLYeFpiQj1Ts++KG0
EzHw+M7WfqGgyHZeWZ0rOeT9/m41RgrvCH2AEn1VyqziSF7hKm59uatXAkksp7bx
wAOcQ/u+S0qp7HVObDvSF5YAn0ySkQGc5K3Egm6zZa3PNRKFFRE/QDQ6m/hBVnsq
UND0M1uR09SpBM+cYLKD7n1payVilEQnTBOD5D9TYZA+rlYXWUq2Hg2NTaH1T3Ni
NH0maRaId/XDxuU5fI0CAwEAAaNTMFEwHQYDVR0OBBYEFEBZVHoDUoQqF49ure0W
In0YEMI4MB8GA1UdIwQYMBaAFEBZVHoDUoQqF49ure0WIn0YEMI4MA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAETWH/TtPbtK59EvInlmmcCSKpky
X67j8xeqcCYaqzqpghq+DIZO+s4HU8XpRm/la9DOs5t9yl+4xzHrFiEBL0UTJuGK
FhYcZ+kJXJ+O1yUL+X4JjXS0BPP/2ClmwFQBWRWVewi+2YpMCYXj4yMwQhEHHXrQ
xe68ELE/qvIG9YAQvSmFN6eV7QyRE/olcdM+T9VUHmjtBO/nJrX9ZZYk7tiXZW14
u25EMAZEEPdtWW05QTW6EfhnwCkjV6HEKLqZZNPbIYXtLJ5/8BsF24YvnR/QpWgU
GYoe0mCDHLZ1aqFZZTp521DONLd2kUrbh22/4qqvAFe137XO2gB/V5QTG9U=
-----END CERTIFICATE-----
)";

// ── Synthetic: v1-shaped cert, no keyUsage extension at all ─────────────────
//
// (openssl req -x509 with no -addext adds only a default subjectKeyIdentifier
// -- no basicConstraints, no keyUsage -- so this exercises the genuinely
// absent-extension path, distinct from the "extension present but empty"
// case, which this CLI/library combination cannot produce.)
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=noext' \
//     -sha256 -out no_ext.pem
// $ openssl x509 -noout -ext keyUsage -in no_ext.pem 2>/dev/null   # stdout:
//   (nothing -- "No extensions in certificate" went to stderr, discarded)
constexpr const char* kNoKeyUsageExtPem = R"(-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIUSb7mT008267ZjI7O5QB5fANaGh4wDQYJKoZIhvcNAQEL
BQAwEDEOMAwGA1UEAwwFbm9leHQwHhcNMjYwODE3MTAzOTA3WhcNMzYwODE0MTAz
OTA3WjAQMQ4wDAYDVQQDDAVub2V4dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAIZYUKgW/1gMSroZDWHvuLXhl9F9qIC50X6NWDHNkP+G+iic2aMewuLC
Olxc1EVD6uZ6oD4VDvtOuWMT9/puhkedtJcXg7kc9Rs5WjBtYeHovzAtaWhMqVXC
qKY7czFIj0UkrIoNnLlru16R+weLVkUJXrj9rT+mn68l9IL6II3JNBvANrmiUp7T
aLdfm61XEwWt2E23E9irnLJgmSGd9f85XPKSbVXSYPSARgYyyzG5QFSydwZSFH4C
9WmAm+smxfSAx82Q0IreDed9kavMNDiuYeumAbbp3PLxdqVgkLhS+0WIbOKnCnrp
adkPv/JURsPgKKtuBGgY6Nd8bdoZ+Z8CAwEAAaNTMFEwHQYDVR0OBBYEFGkjNub4
dy1TdGE2mK+5f5R5Fih1MB8GA1UdIwQYMBaAFGkjNub4dy1TdGE2mK+5f5R5Fih1
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADXhQ0QZC+cruizk
hwqgtvk7ASStDxjh/n4rMDbPs1+x6FAQ+bGUNy9n1B6rf3IX7j3EPgXI15KnavP1
sqldenX/XBwy6uWjQ5Sl0DC5dMDNRK6MJDj83/o47cYpGa/JuMjsNlngBPaX+ef7
M8bqjlvBXrYrTCJLW4b04jhy+aMy3MeNHl/AOC51VUNeQdr2puqOE0Kx/csmrI2S
Z8U1iEtJWnqoWYsj5mc++aIFHw+sG3u58r8z+WIKwt9HqObtbT8HYOxSrTT0KU7G
wRjgAQNWwU/JryCvU2xVIEY/UhUkhz9SZRmJl+npj9dXPmzVSBnmpYrVzVWmDROm
fr/0KLM=
-----END CERTIFICATE-----
)";

// ── Synthetic: CRITICAL multi-bit key usage -- the architect-pinned target ──
//
// $ openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=criticalku' \
//     -addext 'keyUsage=critical,digitalSignature,keyEncipherment,cRLSign' \
//     -sha256 -out critical_ku.pem
// $ openssl x509 -noout -ext keyUsage -in critical_ku.pem
//   X509v3 Key Usage: critical
//       Digital Signature, Key Encipherment, CRL Sign
constexpr const char* kCriticalMultiBitKeyUsagePem = R"(-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIUWbNW13WUBR2hz8nzVbvRCxwMQg4wDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKY3JpdGljYWxrdTAeFw0yNjA4MTcxMDM5MjNaFw0zNjA4
MTQxMDM5MjNaMBUxEzARBgNVBAMMCmNyaXRpY2Fsa3UwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCao919vrCZk90uzLh+P0BXeeJrQ4saalNARe8w0XiS
5R3CglXNIZdsGh2xnfg9bLL9e+qPdl3abYW4HYj2K5tL24OHPZHClk/+YsocOGe1
nUrM1Zf5sRXYf6nfMQJaxOqdAkNt1u1FRKUo4lZkpeNXtK3d7wUOnv84GOP6ydao
R68U2pI4Yx6EQGDgu4UlwZjX/naFpMBvU8hbcfHOHRraamwaZ6l1pDtA9hfvxfsP
+p1wrmaR8n4AwoFdPMw3T2H63jiyjqkhpIokUkiYxZb/xqieM/54ejqVG2BNdN36
voe6OCNUHSV6s3Wd9L7p6oNPYSOnS01UGC6Jyt+M9hplAgMBAAGjYzBhMB0GA1Ud
DgQWBBQykkULzm7JliqyzSyLpUux9LOP9zAfBgNVHSMEGDAWgBQykkULzm7Jliqy
zSyLpUux9LOP9zAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBojANBgkq
hkiG9w0BAQsFAAOCAQEAepMM1+fL+HRxUmK/+WBuuZgM0yzdlzFwbSgostJFkdwn
UI3Vii/q1tkBVcYqftAw6JP1vrfJhr11yDIdqWrAm37ofeYEa1up9XGE7TQIawlI
K7n/OX5m823MqGNu8LLQod5EnQNZmTM1J0cykSExejrTXuDn8ANzt15Jp2BzibPz
E76YhF7Y2pLrFmX557GVkchYxTREwOgwPkqPeOyhKqP0NoWz2b+4ZF+2Z6US+aPN
Lus9ISvDfxRQXg5nvvuxHtPY7fkLZM+9MLefPqUg+XFPG7jHK4NdPrPIO1EpjOqr
1ZLiOcgupW9nNP/wgooMMCZFNrGHQu2iog25BM+72g==
-----END CERTIFICATE-----
)";

// ── Synthetic: ECDSA (P-256) cert, no keyUsage extension ────────────────────
//
// $ openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
//     -days 3650 -subj '/CN=ecdsa-cert/O=Yuzu' -sha256 -out ecdsa.pem
// $ openssl x509 -noout -subject -issuer -serial -fingerprint -sha1 -ext keyUsage -in ecdsa.pem
//   subject=CN=ecdsa-cert, O=Yuzu
//   issuer=CN=ecdsa-cert, O=Yuzu
//   serial=5ADDA35CA512C4386EE0ED2AB71B31229AA395A7
//   sha1 Fingerprint=05:38:E4:CE:B0:7E:03:BE:AD:9B:E9:B4:1A:FC:B1:74:65:70:07:1B
//   (no keyUsage extension -> "No extensions in certificate" on stderr)
constexpr const char* kEcdsaCertPem = R"(-----BEGIN CERTIFICATE-----
MIIBnDCCAUOgAwIBAgIUWt2jXKUSxDhu4O0qtxsxIpqjlacwCgYIKoZIzj0EAwIw
JDETMBEGA1UEAwwKZWNkc2EtY2VydDENMAsGA1UECgwEWXV6dTAeFw0yNjA4MTcx
MDM5MzFaFw0zNjA4MTQxMDM5MzFaMCQxEzARBgNVBAMMCmVjZHNhLWNlcnQxDTAL
BgNVBAoMBFl1enUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARS+3E+VWfLdpNk
HqVtTEDdr+Z6c2wdbF95E+YeaIFkmZqSCUYrN4XqmwRsBX/A3dZAVQ/FMsvUoljU
RVNdF49do1MwUTAdBgNVHQ4EFgQU9KNQ77ZnG9qdycdQKre3Vx/jY+4wHwYDVR0j
BBgwFoAU9KNQ77ZnG9qdycdQKre3Vx/jY+4wDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNHADBEAiAF1ZmteVbI5n01RCT3XnLJLtP7lwzc1arTKeLnF67rugIg
ZEGV+lbamkrP0mQh3RvEnqOf0KyP8JLWdkAqKOhdvQ8=
-----END CERTIFICATE-----
)";

// ── Synthetic 3-cert bundle: A, B, C, each with a distinct thumbprint ───────
//
// $ for n in A B C; do
//     openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=bundle-$n" \
//       -sha256 -out bundle$n.pem
//   done
//   cat bundleA.pem bundleB.pem bundleC.pem > bundle3.pem
//
// $ openssl x509 -noout -subject -fingerprint -sha1 -in bundleA.pem
//   subject=CN=bundle-A
//   sha1 Fingerprint=F3:72:C9:BB:59:3D:12:B6:97:F3:E8:8E:8B:4B:7F:1D:42:84:34:69
// $ openssl x509 -noout -subject -fingerprint -sha1 -in bundleB.pem
//   subject=CN=bundle-B
//   sha1 Fingerprint=15:9A:47:FB:8B:27:84:CD:95:A0:C6:5E:69:A2:0F:58:EA:E3:4C:D7
// $ openssl x509 -noout -subject -fingerprint -sha1 -in bundleC.pem
//   subject=CN=bundle-C
//   sha1 Fingerprint=6C:D0:A1:29:1C:88:30:BF:9D:DE:35:65:50:82:B0:63:DB:EC:A8:00
constexpr const char* kBundleThreeCertsPem = R"(-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUGnXV1pWSVvzkrVkhc1jnE5Xq1FMwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIYnVuZGxlLUEwHhcNMjYwODE3MTAzOTQxWhcNMzYwODE0
MTAzOTQxWjATMREwDwYDVQQDDAhidW5kbGUtQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMh5nUl3TIC7BYLPSYSTk3SdFnbzGXibM5xg1TPAiHHa4w7O
FDVk1M0Rd/VrxjEggULtWdSeMEKqbaX6LeScICjCs0bqtT1DgNKFYRCqHSJ7yRDX
oR+ao4PnL5Qj8SqWsGvNuztYGBGdrfFitUeQph1Gdtsu2jNBRe4jotYpKK8RXmUC
+Qi4k3xUsblCCSPFZTk2lONtn7jIqgwERCkwhDmj/+a0Q05BEpWgXzD71hMoGIbY
yLAGR+0fUSuOMdcZq35P2Yl+Pr2KnebyExvCyOAYFw09jyQP4VL0A1hfANcn5STu
GJPprUbOIep5GjOq5G80yHudlC0M4bwV1Pd+Ii8CAwEAAaNTMFEwHQYDVR0OBBYE
FKEFinMZm4zZFuMBLCqc7dCXCORWMB8GA1UdIwQYMBaAFKEFinMZm4zZFuMBLCqc
7dCXCORWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACZFfb3T
7QK700b3qCZU1PGkrckgnzWe0B6GLZ+3KaetvgJKz1AnJHl7Ni0chF1K3lCFKR9g
LQlWc2j2JsUKcApVon+QtJRartaCmffhcORPJ/v8DdB8+WzNLrKPpUKZZZ572b6F
G+GegFqGe8ZPtdmPoplXcjHj/Eu8svCYJy+2gSRqxn3RVzUtuDB/YcV6UmXOz4O8
trJJixE2ueX9nBp/xvdUieYS+fN2bjfTlrUp7vB9yJ2/ErjN+Br59UbA5gZLNZ9N
AdiBckv0tm+SG2jFYmhFW50ml4czgXSio8FpW7vauhSW0mmDAGpjhX6aPEH4+vt5
D8F3RSnzF8GdnRI=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUUlMvSkJ8eBW9Z9H8OlKvaWpA+2owDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIYnVuZGxlLUIwHhcNMjYwODE3MTAzOTQxWhcNMzYwODE0
MTAzOTQxWjATMREwDwYDVQQDDAhidW5kbGUtQjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKApfU+gp9hVrZVNLmCfh42GcM22iRGFhfm6Exh8wM22vCtw
Tu92V2yIuEHmrOYg3Ua8bzO4NGjeaLPDBdMujEa0yGpv2lmvsSptpG/GmYzdeVKu
JHPn+3fOmONHO69/VqdY9ZlSCIWETcjMjOqzHP4nLPWacS33C6k52eEqDROXRLmB
qtWBFDtteoWXei09+xz7wUc3TpxuzTvzeS3xWcBXfVbXDrnH+vAavl4I8zOHUNa5
7y0N4Yk8JMEsmv0dZ8HfKb4sm3aSprFrkHX2hh3eOvn56p3FBBn+6/9jHqYJ6wet
Idze3xfpl2iPFbmZtSMEL0QRwIscAOFN1VIkMPUCAwEAAaNTMFEwHQYDVR0OBBYE
FERiFiiSnwdQIAVRFvHz722zqO8EMB8GA1UdIwQYMBaAFERiFiiSnwdQIAVRFvHz
722zqO8EMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAH9pvTbD
ICQcnnM0H9WBz0itK4yaXJIyJSjLbcf1xNla/rJlqRoSVy/5CA0Dvss40w6rAz7+
yZ783aBQVDG2rkVdLKuKkgORhtrzOoGik1mk8cOANQafk4jzehUO4Txuk3V0KxMW
yTgjwO2a7lGsSsw5shK//w9NuUpe0Lst6+0h6PXKFNMCDJ7u6YsZaAXt8Pciz6Vk
Vt+pEmikhvEmFdX6vlrYRESyhDkwMsiEs2O0lHIy3NcWZhMGrMHJ4RC5C5crC7bi
KNjfYtw1VHId3ItY6ANE+Y3gVINjOPqtDxiuRWKtvMgy6Tz91fEF3tL7B8tQZqpS
8AIQcK6HCjDqVD0=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUL7MZqUtloLgfzrEgLoPlyDDqstgwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIYnVuZGxlLUMwHhcNMjYwODE3MTAzOTQyWhcNMzYwODE0
MTAzOTQyWjATMREwDwYDVQQDDAhidW5kbGUtQzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALB/3HC9qYBITfbNo5AYQ4eiF47T6yqychfPvRflhuwsNFFJ
IU+r7/1PakWYAEbMSqEgv1/Uky6Q//TQD4G0PhoPRGFLnOlE2r6eAHWkWVJcxPnm
8r3P9xuCn4dlLqxPPPuGhMzNTLMmLj6HXUNTGiddJKQu7yPk3gtxDZdIJZ/LDCyC
dcmJIR0MPg3YDDi9H9ZtOARyhinqJCm3+NSviGAR7IHuAM3LRODGt2pLxhroea/U
BjoZqGc4SI3etWlooOt3VcAhM8owXefs1hvWwRoiLzPm4d22ygevT2YXyCmB+Je1
UojVgjIr2LwUTYvIlD4whP/Zn+D7GsVmoc9ZJRcCAwEAAaNTMFEwHQYDVR0OBBYE
FMn4w4VJzoo7vtN7sqm9OfWb8ttzMB8GA1UdIwQYMBaAFMn4w4VJzoo7vtN7sqm9
OfWb8ttzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKeZ7vz7
XletmmNn2lPJe3u3tYcxeTmgH5mIftYuAN2LhgK+ygw/p0EIfXFNcOkpIMHOduOy
orCAmft+i+IJDCKJVne+VIY1Eb4DOYLUJpv9M507/pimw2NRi6YQ5IJRGKTBUezP
eIOhoz9mqS0i9SbQLv4oWO5TTWl3CqiIZv7i+mSFjUYIcieMT2fZD1Jvc31YqyDa
FDAB+rtSMEC61ukdXVuAHV3+zNQ6Z2Y66FqP0pCjYSwVA3Tlul9VV2orV0kOL6Bv
LuwJ9eVH5KLjY9kIG6Gl7B2E2sSJ2UDC/KPi5Pq5Rty8dwRKWNuSC3+E9LCLZZsW
eXnFkkNcPJENOk0=
-----END CERTIFICATE-----
)";

constexpr const char* kBundleA_Thumbprint = "F372C9BB593D12B697F3E88E8B4B7F1D42843469";
constexpr const char* kBundleB_Thumbprint = "159A47FB8B2784CD95A0C65E69A20F58EAE34CD7";
constexpr const char* kBundleC_Thumbprint = "6CD0A1291C8830BF9DDE35655082B063DBECA800";

std::vector<unsigned char> pem_to_der(const std::string& pem) {
    // Minimal PEM->DER for parse_der_cert() vectors: strip the header/footer
    // markers and base64-decode the body. certificates_x509.hpp's own
    // parse_der_cert() never does this (its caller, the macOS SecItem path,
    // always hands it DER straight from SecCertificateCopyData) -- this
    // helper exists purely so the DER vectors below can be authored as PEM
    // (openssl's native output format) and converted once, here, in the
    // test.
    static const std::string kB64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string body;
    std::istringstream iss(pem);
    std::string line;
    bool in_body = false;
    while (std::getline(iss, line)) {
        if (line.find("-----BEGIN") != std::string::npos) {
            in_body = true;
            continue;
        }
        if (line.find("-----END") != std::string::npos) {
            break;
        }
        if (in_body)
            body += line;
    }
    std::vector<unsigned char> out;
    unsigned int val = 0;
    int bits = 0;
    for (char c : body) {
        if (c == '=')
            break;
        auto pos = kB64.find(c);
        if (pos == std::string::npos)
            continue;
        val = (val << 6) | static_cast<unsigned int>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((val >> bits) & 0xFF));
        }
    }
    return out;
}

} // namespace

// ── parse_pem_certs: single certificate ──────────────────────────────────────

TEST_CASE("parse_pem_certs: real System.keychain capture, single cert", "[certificates_x509]") {
    auto certs = parse_pem_certs(kRealSystemDefaultCertPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].subject == "CN=com.apple.systemdefault, O=System Identity");
    CHECK(certs[0].issuer == "CN=com.apple.systemdefault, O=System Identity");
    CHECK(certs[0].serial == "5AB45DC6");
    CHECK(certs[0].thumbprint == "E363C8FA8D5CC5087456542669F6C633267587F2");
}

TEST_CASE("parse_pem_certs: real capture thumbprint pins uppercase colon-free SHA-1",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kRealSystemDefaultCertPem);
    REQUIRE(certs.size() == 1);
    // openssl's own `-fingerprint -sha1` for this cert:
    //   sha1 Fingerprint=E3:63:C8:FA:8D:5C:C5:08:74:56:54:26:69:F6:C6:33:26:75:87:F2
    // -- colons stripped, case preserved (already uppercase).
    CHECK(certs[0].thumbprint == "E363C8FA8D5CC5087456542669F6C633267587F2");
}

TEST_CASE("parse_pem_certs: real capture dates/key-usage", "[certificates_x509]") {
    auto certs = parse_pem_certs(kRealSystemDefaultCertPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].not_before == "2022-10-08");
    CHECK(certs[0].not_after == "2042-10-03");
    CHECK(certs[0].key_usage == "Digital Signature, Key Encipherment, Data Encipherment");
}

// ── parse_pem_certs: subject/issuer rendering (XN_FLAG_SEP_CPLUS_SPC) ───────

TEST_CASE("parse_pem_certs: subject with comma and unescaped '+' matches CLI default nameopt",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kCommaPlusSubjectPem);
    REQUIRE(certs.size() == 1);
    // Architect-pinned target: the comma inside "Yuzu, Inc." is not escaped
    // or reordered (that would be XN_FLAG_RFC2253's
    // "CN=t\+e,O=Yuzu\, Inc.,C=GB"), and "t+e" is not quoted (that would be
    // XN_FLAG_ONELINE's `CN = "t+e"`).
    CHECK(certs[0].subject == "C=GB, O=Yuzu, Inc., CN=t+e");
    CHECK(certs[0].issuer == "C=GB, O=Yuzu, Inc., CN=t+e");
}

TEST_CASE("parse_pem_certs: multi-valued RDN renders with ' + ' separator",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kMultiValuedRdnPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].subject == "C=US, CN=multi + O=RdnCo");
}

TEST_CASE("parse_pem_certs: UTF-8 subject", "[certificates_x509]") {
    auto certs = parse_pem_certs(kUtf8SubjectPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].subject == "C=JP, O=\xE3\x83\xA6\xE3\x82\xBA\xE6\xA0\xAA\xE5\xBC\x8F\xE4\xBC"
                              "\x9A\xE7\xA4\xBE, CN=caf\xC3\xA9");
}

// ── parse_pem_certs: serial rendering (i2a_ASN1_INTEGER) ────────────────────

TEST_CASE("parse_pem_certs: serial with a DER-boundary padding byte matches CLI",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kLeadingZeroSerialPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].serial == "80ABCDEF");
}

TEST_CASE("parse_pem_certs: serial value zero pins i2a_ASN1_INTEGER over BN_bn2hex",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kSerialZeroPem);
    REQUIRE(certs.size() == 1);
    // i2a_ASN1_INTEGER prints the single content byte 0x00 as "00" -- the
    // divergent case from ASN1_INTEGER_to_BN+BN_bn2hex, whose zero-magnitude
    // BIGNUM would print as bare "0" instead. See certificates_x509.hpp's
    // extract_serial() comment.
    CHECK(certs[0].serial == "00");
}

// ── parse_pem_certs: key_usage (X509V3_EXT_print + old line-selection) ─────

TEST_CASE("parse_pem_certs: absent keyUsage extension yields (none)", "[certificates_x509]") {
    auto certs = parse_pem_certs(kNoKeyUsageExtPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].key_usage == "(none)");
}

TEST_CASE("parse_pem_certs: critical multi-bit keyUsage matches architect-pinned target",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kCriticalMultiBitKeyUsagePem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].key_usage == "Digital Signature, Key Encipherment, CRL Sign");
}

// ── parse_pem_certs: algorithm-agnostic (ECDSA) ──────────────────────────────

TEST_CASE("parse_pem_certs: ECDSA (P-256) cert parses identically to RSA", "[certificates_x509]") {
    auto certs = parse_pem_certs(kEcdsaCertPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].subject == "CN=ecdsa-cert, O=Yuzu");
    CHECK(certs[0].serial == "5ADDA35CA512C4386EE0ED2AB71B31229AA395A7");
    CHECK(certs[0].thumbprint == "0538E4CEB07E03BEAD9BE9B41AFCB1746570071B");
    CHECK(certs[0].key_usage == "(none)");
}

// ── parse_pem_certs: expiry is just date text, no special-casing ────────────

TEST_CASE("parse_pem_certs: expired cert still parses -- expiry is a caller concern",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kExpiredCertPem);
    REQUIRE(certs.size() == 1);
    CHECK(certs[0].not_before == "2020-01-01");
    CHECK(certs[0].not_after == "2021-01-01");
}

// ── parse_pem_certs: cardinality parity (WP-B part 4) ───────────────────────

TEST_CASE("parse_pem_certs: a 3-cert bundle returns all 3, in file order",
          "[certificates_x509]") {
    auto certs = parse_pem_certs(kBundleThreeCertsPem);
    REQUIRE(certs.size() == 3);
    CHECK(certs[0].subject == "CN=bundle-A");
    CHECK(certs[1].subject == "CN=bundle-B");
    CHECK(certs[2].subject == "CN=bundle-C");
    CHECK(certs[0].thumbprint == kBundleA_Thumbprint);
    CHECK(certs[1].thumbprint == kBundleB_Thumbprint);
    CHECK(certs[2].thumbprint == kBundleC_Thumbprint);
}

TEST_CASE("parse_pem_certs cardinality parity: a caller consuming only .front() "
          "never selects the bundle's 2nd certificate",
          "[certificates_x509]") {
    // This is the parity contract certificates_plugin.cpp's
    // first_cert_of_file() depends on: `openssl x509 -in <file>` (the
    // subprocess this header replaces) reads ONLY the first PEM block in a
    // file, so list_certs_linux emits exactly one row per file and
    // delete_cert_linux matches only a file's FIRST certificate.
    // parse_pem_certs() itself returns every certificate a bundle contains
    // (proven above) -- it is the CALLER's job to consume only certs.front().
    // This test proves that discipline is safe: requesting bundleB's
    // thumbprint (the bundle's 2nd certificate) against only the front()
    // element never matches, so a delete keyed on that thumbprint against
    // this bundle file would correctly report "not found" rather than
    // deleting the file (which would silently also discard bundleA and
    // bundleC -- a multi-cert CA bundle turned into a bulk trust-anchor
    // removal).
    auto certs = parse_pem_certs(kBundleThreeCertsPem);
    REQUIRE(certs.size() == 3);
    const auto& first_only = certs.front();
    CHECK(first_only.thumbprint == kBundleA_Thumbprint);
    CHECK_FALSE(first_only.thumbprint == kBundleB_Thumbprint);
    CHECK_FALSE(first_only.thumbprint == kBundleC_Thumbprint);
}

// ── parse_pem_certs: garbage / malformed input never throws ─────────────────

TEST_CASE("parse_pem_certs: garbage input yields an empty vector, not a throw",
          "[certificates_x509]") {
    auto certs = parse_pem_certs("this is not a certificate at all, just plain text");
    CHECK(certs.empty());

    auto certs_empty = parse_pem_certs("");
    CHECK(certs_empty.empty());
}

TEST_CASE("parse_pem_certs: PEM header with truncated base64 body yields an empty vector",
          "[certificates_x509]") {
    // Real header/footer markers, but the base64 body is cut off mid-block --
    // PEM_read_bio_X509 must fail cleanly on its first (only) call rather
    // than crash or hang.
    constexpr const char* kTruncated =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDPzCCAiegAwIBAgIEWrRdxjANBgkqhkiG9w0BAQsFADA8MSAwHgYDVQQDDBdj\n"
        "b20uYXBwbGUuc3lz\n"
        "-----END CERTIFICATE-----\n";
    auto certs = parse_pem_certs(kTruncated);
    CHECK(certs.empty());
}

// ── parse_der_cert: the macOS SecItem DER decode path ────────────────────────

TEST_CASE("parse_der_cert: valid DER decodes to the same fields as the PEM parse",
          "[certificates_x509]") {
    auto der = pem_to_der(kEcdsaCertPem);
    REQUIRE_FALSE(der.empty());
    auto cert = parse_der_cert(std::span<const unsigned char>(der.data(), der.size()));
    REQUIRE(cert.has_value());
    CHECK(cert->subject == "CN=ecdsa-cert, O=Yuzu");
    CHECK(cert->serial == "5ADDA35CA512C4386EE0ED2AB71B31229AA395A7");
}

// Regression vector for the adversarial-review finding that `parse_der_cert`
// accepted a valid certificate followed by arbitrary trailing bytes while
// documenting a "valid single DER certificate" contract. d2i_X509 decodes the
// first object and advances its cursor past only that object, so without an
// explicit end-of-span check the caller silently gets the first certificate of
// a framed or concatenated buffer and believes the whole buffer was validated.
// Both halves matter: the exact-length input must still parse (this is the
// shape the production SecItem caller always supplies, so a too-strict check
// would break the live path), and every non-exact variant must be rejected.
TEST_CASE("parse_der_cert: rejects trailing bytes after a valid certificate",
          "[certificates_x509]") {
    auto der = pem_to_der(kEcdsaCertPem);
    REQUIRE_FALSE(der.empty());

    // Exact length -- the production shape -- still parses.
    REQUIRE(parse_der_cert(std::span<const unsigned char>(der.data(), der.size())).has_value());

    // One trailing byte is enough to make the buffer "not exactly one cert".
    auto one_extra = der;
    one_extra.push_back(0x00);
    CHECK_FALSE(
        parse_der_cert(std::span<const unsigned char>(one_extra.data(), one_extra.size()))
            .has_value());

    // Arbitrary trailing garbage.
    auto junk = der;
    for (unsigned char b : {0x00u, 0xFFu, 0xDEu, 0xADu, 0xBEu, 0xEFu})
        junk.push_back(b);
    CHECK_FALSE(
        parse_der_cert(std::span<const unsigned char>(junk.data(), junk.size())).has_value());

    // Two concatenated certificates: the caller asked for ONE, so this is a
    // rejection, not "return the first".
    auto concatenated = der;
    concatenated.insert(concatenated.end(), der.begin(), der.end());
    CHECK_FALSE(parse_der_cert(
                    std::span<const unsigned char>(concatenated.data(), concatenated.size()))
                    .has_value());

    // Truncating the certificate is a decode failure, not a trailing-byte one
    // -- pinned here so the two rejection reasons can't silently merge.
    std::vector<unsigned char> truncated(der.begin(), der.begin() + (der.size() / 2));
    CHECK_FALSE(
        parse_der_cert(std::span<const unsigned char>(truncated.data(), truncated.size()))
            .has_value());
}

TEST_CASE("parse_der_cert: empty/garbage input yields std::nullopt, not a throw",
          "[certificates_x509]") {
    std::vector<unsigned char> empty;
    CHECK_FALSE(parse_der_cert(std::span<const unsigned char>(empty.data(), empty.size()))
                    .has_value());

    std::vector<unsigned char> garbage{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE, 0xEF};
    CHECK_FALSE(
        parse_der_cert(std::span<const unsigned char>(garbage.data(), garbage.size())).has_value());
}
