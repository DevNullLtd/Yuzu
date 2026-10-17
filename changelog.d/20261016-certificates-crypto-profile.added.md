- **Certificate inventory reports each certificate's crypto profile (breaking for fixed-width row
  parsers).** `security.certificates.list` and `security.certificates.details` gain three columns,
  appended after `key_usage`: `key_algorithm` (e.g. `RSA`, `EC P-256`, `Ed25519`, `ML-DSA-65`),
  `key_bits` and `signature_algorithm` (e.g. `sha256WithRSAEncryption`, `sha1WithRSAEncryption`,
  `md5WithRSAEncryption`). Operators can now find RSA-1024, SHA-1/MD5-signed and
  quantum-vulnerable certificates across Windows, Linux and macOS from one query. All three OS
  legs name algorithms through one shared OID table, so the same certificate reports the same
  values everywhere; an algorithm the table does not name is reported as its dotted OID. The
  first eight fields keep their position, but automation that expects exactly eight fields, or
  treats the last field as `key_usage`, must accept eleven. Agents before `certificates` plugin
  1.1.0 keep sending eight, and existing servers keep the seeded 1.1.0 definitions (#2555); see
  the upgrade note in `docs/user-manual/server-admin.md`. Also corrects a stale
  `certificates_plugin.cpp` line citation in a `filesystem_posture` source comment.
