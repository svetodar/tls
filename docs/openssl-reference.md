# OpenSSL reference sources

The library is implemented from the relevant standards and from the OpenSSL
sources as an independent reference for edge cases and test vectors. OpenSSL
is **not** linked, and none of its C sources are part of this repository.

## Obtaining the sources

The reference used during development is OpenSSL **3.5.9**:

```bash
mkdir -p OpenSSL
cd OpenSSL
curl -LO https://www.openssl.org/source/openssl-3.5.9.tar.gz
tar xzf openssl-3.5.9.tar.gz
```

The resulting tree lives in `./OpenSSL/` at the repository root. That path is
git-ignored: it is a local, read-only reference.

Some tests and the fixture generator also use the test certificates shipped
with these sources (`OpenSSL/openssl-3.5.9/test/certs/`). When the directory is
missing, `make fixtures` skips that step and the committed `openssl_*.der`
vectors are kept.

## Where to look

| Area | OpenSSL paths |
| --- | --- |
| BN / bignum | `crypto/bn/bn_mul.c`, `bn_div.c`, `bn_mod.c`, `bn_exp.c`, `bn_gcd.c`, `bn_conv.c`, `bn_rand.c` |
| CSPRNG | `crypto/rand/rand_pool.c`, `rand_lib.c`, `drbg.c`, `rand_fork.c` |
| SHA-2 / HMAC | `crypto/sha/sha256.c`, `crypto/sha/sha512.c`, `crypto/hmac/hmac.c` |
| AES | `crypto/aes/aes_core.c`, `aes_cbc.c`, `aesgcm.c`, `crypto/modes/gcm128.c` |
| ChaCha20 / Poly1305 | `crypto/chacha/chacha_enc.c`, `crypto/poly1305/poly1305.c`, `crypto/evp/e_chacha20_poly1305.c` |
| RSA | `crypto/rsa/` (`rsa_lib.c`, `rsa_crpt.c`, `rsa_sign.c`, `rsa_gen.c`, `rsa_asn1.c`), `crypto/evp/e_pkey_rsa.c` |
| EC / ECDH / ECDSA | `crypto/ec/ec_key.c`, `ec_mult.c`, `ecp_nistp256.c`, `ecp_nistp384.c`, `crypto/ecdh/`, `crypto/ecdsa/` |
| DH | `crypto/dh/dh_lib.c`, `dh_gen.c`, `dh_key.c`, `dh_ameth.c` |
| ASN.1 | `crypto/asn1/tasn_dec.c`, `tasn_enc.c`, `a_int.c`, `a_objid.c`, `a_time.c`, `a_str.c` |
| X.509 | `crypto/x509/x509_d2.c`, `x509_lu.c`, `x509_vfy.c`, `x509_cmp.c`, `v3_ext.c`, `x509_spki.c` |
| TLS 1.2 | `ssl/t1_lib.c`, `t1_enc.c`, `t1_trce.c`, `ssl/record/rec_layer_s3.c`, `ssl/ssl_ciph.c`, `ssl/ssl_rsa.c` |
| TLS 1.3 | `ssl/tls13_enc.c`, `ssl/t1_lib.c`, `ssl/record/rec_layer_tls.c`, `ssl/ssl_ciph.c` |

Each task specification under [`docs/tasks/`](tasks/) lists the exact files
relevant to that work item.

## External standards used as the primary reference

- NIST FIPS 180-4 (SHA-2), FIPS 197 (AES), SP 800-38A/38D (CBC/GCM),
  SP 800-90A (HMAC-DRBG), SP 800-56B (RSADP), FIPS 186-4 (RSASP1);
- RFC 2104 (HMAC), RFC 4231 (HMAC-SHA-2 vectors), RFC 8439
  (ChaCha20-Poly1305), RFC 8017 (PKCS#1), RFC 6090 (ECDSA/ECDH vectors),
  RFC 3526/5114 (DH groups);
- RFC 5246 (TLS 1.2), RFC 7627 (extended master secret), RFC 5288 (AES-GCM),
  RFC 7905 (ChaCha20-Poly1305), RFC 8446 (TLS 1.3);
- X.690 (DER), RFC 5280 (X.509 / PKIX).
