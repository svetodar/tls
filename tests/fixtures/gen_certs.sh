#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# ============================================================
# RSA CA (self-signed)
# ============================================================
openssl genrsa -out ca_rsa.key 2048 2>/dev/null

openssl req -x509 -new -key ca_rsa.key \
  -sha256 -days 3650 \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test CA/CN=TLS Test RSA CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca_rsa.crt

# ============================================================
# RSA Leaf (signed by CA)
# ============================================================
openssl genrsa -out leaf_rsa.key 2048 2>/dev/null

openssl req -new -key leaf_rsa.key \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test/CN=localhost" \
  -out leaf_rsa.csr

cat > leaf_rsa.ext << 'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:example.com, DNS:*.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXT

openssl x509 -req -in leaf_rsa.csr -CA ca_rsa.crt -CAkey ca_rsa.key \
  -CAcreateserial -days 365 -sha256 \
  -extfile leaf_rsa.ext \
  -out leaf_rsa.crt 2>/dev/null

# ============================================================
# Non-CA RSA leaf (CA:FALSE, no SAN) signed by the RSA CA
# ============================================================
openssl genrsa -out nonca_rsa.key 2048 2>/dev/null

openssl req -new -key nonca_rsa.key \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test/CN=nonca.example.com" \
  -out nonca_rsa.csr

cat > nonca_rsa.ext << 'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXT

openssl x509 -req -in nonca_rsa.csr -CA ca_rsa.crt -CAkey ca_rsa.key \
  -CAserial ca_rsa.srl -days 365 -sha256 \
  -extfile nonca_rsa.ext \
  -out nonca_rsa.crt 2>/dev/null

# ============================================================
# Hostname-mismatch RSA leaf (SAN does not contain localhost)
# ============================================================
openssl genrsa -out mismatch_rsa.key 2048 2>/dev/null

openssl req -new -key mismatch_rsa.key \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test/CN=wrong.example.com" \
  -out mismatch_rsa.csr

cat > mismatch_rsa.ext << 'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:wrong.example.com, DNS:other.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXT

openssl x509 -req -in mismatch_rsa.csr -CA ca_rsa.crt -CAkey ca_rsa.key \
  -CAserial ca_rsa.srl -days 365 -sha256 \
  -extfile mismatch_rsa.ext \
  -out mismatch_rsa.crt 2>/dev/null

# ============================================================
# Expired RSA leaf (validity window entirely in the past)
# ============================================================
openssl genrsa -out expired_rsa.key 2048 2>/dev/null

openssl req -new -key expired_rsa.key \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test/CN=localhost" \
  -out expired_rsa.csr

cat > expired_rsa.ext << 'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXT

openssl x509 -req -in expired_rsa.csr -CA ca_rsa.crt -CAkey ca_rsa.key \
  -CAserial ca_rsa.srl -sha256 \
  -not_before 20250101000000Z -not_after 20250601000000Z \
  -extfile expired_rsa.ext \
  -out expired_rsa.crt 2>/dev/null

# ============================================================
# ECDSA CA (self-signed, P-256)
# ============================================================
openssl ecparam -name prime256v1 -genkey -noout -out ca_ec.key 2>/dev/null

openssl req -x509 -new -key ca_ec.key \
  -sha256 -days 3650 \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test CA/CN=TLS Test EC CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca_ec.crt

# ============================================================
# ECDSA Leaf (signed by EC CA)
# ============================================================
openssl ecparam -name prime256v1 -genkey -noout -out leaf_ec.key 2>/dev/null

openssl req -new -key leaf_ec.key \
  -subj "/C=US/ST=Test/L=Test/O=TLS Test/CN=localhost" \
  -out leaf_ec.csr

cat > leaf_ec.ext << 'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:example.com, DNS:*.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXT

openssl x509 -req -in leaf_ec.csr -CA ca_ec.crt -CAkey ca_ec.key \
  -CAcreateserial -days 365 -sha256 \
  -extfile leaf_ec.ext \
  -out leaf_ec.crt 2>/dev/null

# ============================================================
# DER copies (for ASN.1 parser tests)
# ============================================================
openssl x509 -in ca_rsa.crt  -outform DER -out ca_rsa.der
openssl x509 -in leaf_rsa.crt -outform DER -out leaf_rsa.der
openssl x509 -in nonca_rsa.crt -outform DER -out nonca_rsa.der
openssl x509 -in mismatch_rsa.crt -outform DER -out mismatch_rsa.der
openssl x509 -in expired_rsa.crt -outform DER -out expired_rsa.der
openssl x509 -in ca_ec.crt   -outform DER -out ca_ec.der
openssl x509 -in leaf_ec.crt -outform DER -out leaf_ec.der

# ============================================================
# OpenSSL test/certs → DER (for X.509 + ASN.1 tests)
# ============================================================
# The script has already cd'd into tests/fixtures, so the reference OpenSSL
# sources live two levels up (repo root).
OPENSSL_CERTS="../../OpenSSL/openssl-3.5.9/test/certs"
if [ -d "$OPENSSL_CERTS" ]; then
  for pair in \
    "ca-cert.pem:openssl_ca.der" \
    "ca-cert-ec-named.pem:openssl_ca_ec.der" \
    "cert-key-cert.pem:openssl_leaf.der" \
    "ca-expired.pem:openssl_expired.der" \
    "ca-nonca.pem:openssl_nonca.der" \
    "bad.pem:openssl_bad.der" \
    "ca-pss-cert.pem:openssl_ca_pss.der" \
    "ca-cert-md5.pem:openssl_ca_md5.der"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    openssl x509 -in "$OPENSSL_CERTS/$src" -outform DER -out "$dst"
  done
  echo "Converted 8 OpenSSL test certs to DER."
else
  echo "WARNING: $OPENSSL_CERTS not found, skipping OpenSSL cert conversion."
fi

# ============================================================
# Hand-crafted DER test vectors (for ASN.1 parser tests)
# ============================================================
python3 - << 'PYEOF'
import sys

def w(name, data):
    with open(name, 'wb') as f:
        f.write(data)

# --- INTEGER ---
w("der_int_zero.der",    bytes([0x02, 0x01, 0x00]))
w("der_int_127.der",     bytes([0x02, 0x01, 0x7F]))
w("der_int_128.der",     bytes([0x02, 0x02, 0x00, 0x80]))
w("der_int_neg1.der",    bytes([0x02, 0x01, 0xFF]))
w("der_int_256.der",     bytes([0x02, 0x02, 0x01, 0x00]))
w("der_int_long.der",    bytes([0x02, 0x81, 0x80]) + bytes([0x01]) * 128)

# --- NULL ---
w("der_null.der",        bytes([0x05, 0x00]))

# --- OID ---
w("der_oid_1_2_840.der",      bytes([0x06, 0x03, 0x2A, 0x86, 0x48]))
w("der_oid_1_2_3_4_1.der",    bytes([0x06, 0x04, 0x2A, 0x03, 0x04, 0x01]))
w("der_oid_sha256_rsa.der",   bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0F]))

# --- Time ---
utc = b"201212201650Z"
w("der_utctime.der",         bytes([0x17, len(utc)]) + utc)
gt = b"21201213201650Z"
w("der_generalizedtime.der", bytes([0x18, len(gt)]) + gt)

# --- Strings ---
w("der_octet_hello.der",  bytes([0x04, 0x05]) + b"hello")
w("der_octet_empty.der",  bytes([0x04, 0x00]))
w("der_bitstring.der",    bytes([0x03, 0x02, 0x01, 0x5A]))
w("der_printable.der",    bytes([0x13, 0x0B]) + b"Test String")
w("der_ia5.der",          bytes([0x16, 0x0F]) + b"hello@world.com")
utf8 = b"h\xc3\xa9llo"
w("der_utf8.der",         bytes([0x12, len(utf8)]) + utf8)

# --- SEQUENCE / SET ---
w("der_seq_empty.der",    bytes([0x30, 0x00]))
int1 = bytes([0x02, 0x01, 0x01]); int2 = bytes([0x02, 0x01, 0x02])
w("der_seq_two_ints.der", bytes([0x30, 0x06]) + int1 + int2)
w("der_set_two_ints.der", bytes([0x31, 0x06]) + int1 + int2)
inner = bytes([0x30, 0x03, 0x02, 0x01, 0x2A])
w("der_nested_seq.der",   bytes([0x30, 0x07]) + inner + bytes([0x05, 0x00]))

# --- Boolean ---
w("der_bool_true.der",    bytes([0x01, 0x01, 0xFF]))
w("der_bool_false.der",   bytes([0x01, 0x01, 0x00]))

# --- Context-specific / Application tags ---
w("der_app12.der",              bytes([0x4C, 0x03, 0x02, 0x01, 0x01]))
w("der_ctx0.der",               bytes([0x80, 0x03, 0x02, 0x01, 0x01]))
w("der_ctx0_constructed.der",   bytes([0xA0, 0x03, 0x02, 0x01, 0x01]))

# --- Error / edge cases ---
w("der_truncated.der",    bytes([0x30, 0x0A, 0x02, 0x01, 0x01]))
w("der_single_byte.der",  bytes([0x30]))
w("der_trunc2.der",       bytes([0x02, 0x05, 0x01, 0x02]))
w("der_indefinite.der",   bytes([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]))

print("Created 31 DER test vectors.")
PYEOF

# ============================================================
# Cleanup temp files
# ============================================================
rm -f leaf_rsa.csr leaf_ec.csr leaf_rsa.ext leaf_ec.ext \
      nonca_rsa.csr nonca_rsa.ext mismatch_rsa.csr mismatch_rsa.ext \
      expired_rsa.csr expired_rsa.ext ca_rsa.srl ca_ec.srl

echo "=== Generated fixtures ==="
ls -la *.crt *.key *.der
