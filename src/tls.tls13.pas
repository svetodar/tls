{ SPDX-License-Identifier: Apache-2.0 }
unit tls.tls13;

{TLS 1.3 client (RFC 8446) for task 13 (docs/tasks/13-tls13.md).

  Milestone F. Layer 3: builds on tasks 01-11 (primitives, RSA, EC, ASN.1,
  X.509, certificate store) and on task 12 (ITLSTransport, record layer,
  handshake framing) from tls.tls12.

  Scope: client side only, 1-RTT handshake, AEAD only, no renegotiation,
  no 0-RTT / early data, no HelloRetryRequest (an explicit error is raised
  instead of silently restarting), no PSK resumption.

  The unit is transport-agnostic: it talks to the network only through
  tls.tls12.ITLSTransport and stays testable in memory.

  This unit is filled in by the subsequent steps of milestone F:
    - HKDF-Extract / HKDF-Expand (RFC 5869) over HMAC-SHA256/384 and
      HKDF-Expand-Label / Derive-Secret (RFC 8446, 7.1);
    - TLS 1.3 constants: version 0x0304, cipher suites 0x1301/0x1302/0x1303,
      handshake message and extension codes;
    - key_share on P-256/P-384 (shared secret = X coordinate of (EC)DHE);
    - ClientHello with SNI, supported_versions, supported_groups, key_share
      and signature_algorithms;
    - ServerHello parsing, EncryptedExtensions, Certificate (TLS 1.3 format)
      and CertificateVerify verification with the transcript hash;
    - key schedule: early/handshake/master secrets and traffic secrets;
    - record layer for 1.3: nonce = iv XOR seq, AAD = record header,
      inner plaintext = content || content_type || zero padding, legacy
      ChangeCipherSpec records are ignored;
    - Finished computation and constant-time comparison of verify_data;
    - TTLS13Client (Connect/Send/Recv/Shutdown/PendingBytes/CipherSuite)
      and ETLS13Error for unsupported suites, signature schemes and HRR. }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, tls.bn, tls.ec, tls.rsa,
  tls.sha2, tls.hmac, tls.rand, tls.x509, tls.certstore, tls.tls12;

type
  { Typed error raised by the TLS 1.3 client and its parsers. It derives
    from ETLS12Error so that code handling the record layer and the
    handshake framing from tls.tls12 keeps catching 1.3 failures as well.
    Malformed, truncated or unsupported input always raises it instead of
    returning partial data: an unsupported cipher suite or named group, a
    signature scheme this client cannot verify, and a HelloRetryRequest all
    fail with an explicit message, never with silent misbehaviour. }
  ETLS13Error = class(ETLS12Error);

{--- HKDF (RFC 5869) ----------------------------------------------------- }

{Output length of the underlying hash, in bytes: SHA-256 -> 32,
  SHA-384 -> 48, SHA-512 -> 64. Raises an exception for an unknown kind. }
function TLS13HashLen(AHash: THashKind): Integer;

{HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM) (RFC 5869, 2.2).
  An empty salt is replaced by HashLen zero bytes, as RFC 5869 prescribes
  (2.2: "if not provided, it is set to a string of HashLen zeros"). }
function HKDFExtract(AHash: THashKind; const Salt, IKM: TBytes): TBytes;

{HKDF-Expand(PRK, info, L) (RFC 5869, 2.3):
    T(0) = empty; T(i) = HMAC-Hash(PRK, T(i-1) || info || byte(i));
    OKM  = first L bytes of T(1) || T(2) || ... || T(N), N = ceil(L/HashLen).
  ALen = 0 yields an empty result. Raises an exception if ALen is negative
  or greater than 255 * HashLen, if PRK is shorter than HashLen, or if the
  hash kind is unknown. TLS 1.3 uses SHA-256 and SHA-384. }
function HKDFExpand(AHash: THashKind; const PRK, Info: TBytes;
  ALen: Integer): TBytes;

{--- HKDF-Expand-Label (RFC 8446, 7.1) ----------------------------------- }

{ Every TLS 1.3 label is prefixed with this string (RFC 8446, 7.1). }
const
  TLS13LabelPrefix = 'tls13 ';

{ Serializes the HkdfLabel structure consumed by HKDF-Expand-Label
  (RFC 8446, 7.1):

    struct HkdfLabel:
        uint16 length;                // ALen, big endian
        opaque label<7..255>;         // TLS13LabelPrefix || ALabel
        opaque context<0..255>;       // AContext

  ALabel is given without the prefix and must not be empty, so that the
  serialized label satisfies the 7..255 bound; ALen must fit into a
  uint16 and AContext must be at most 255 bytes long. Violations raise an
  exception rather than producing a truncated structure. }
function TLS13HkdfLabel(const ALabel: AnsiString; const AContext: TBytes;
  ALen: Integer): TBytes;

{ HKDF-Expand-Label(Secret, Label, Context, Length) (RFC 8446, 7.1):

    HKDF-Expand-Label(Secret, Label, Context, Length) =
        HKDF-Expand(Secret, HkdfLabel, Length)

  with HkdfLabel serialized by TLS13HkdfLabel. ALabel is passed *without*
  the "tls13 " prefix, which is added here. AContext is the transcript hash
  of the handshake so far (empty for secrets derived from an empty
  transcript); ALen is bounded by HKDF-Expand. Secret must be at least
  HashLen bytes long, as HKDF-Expand requires. }
function HKDFExpandLabel(AHash: THashKind; const Secret: TBytes;
  const ALabel: AnsiString; const AContext: TBytes; ALen: Integer): TBytes;

{--- TLS 1.3 constants (RFC 8446) ---------------------------------------- }

const
  { Protocol version (RFC 8446, 4.2.1 and Appendix B): TLS 1.3 is 0x0304.
    ClientHello and ServerHello carry legacy_version = 0x0303 on the wire
    and negotiate the real version through supported_versions, so the
    legacy value is also made explicit here. }
  TLS13VersionMajor = 3;
  TLS13VersionMinor = 4;
  TLS13Version = (TLS13VersionMajor shl 8) or TLS13VersionMinor;
  TLS13LegacyVersion = $0303;  { legacy_version / legacy_record_version }

  { Cipher suites (RFC 8446, B.4). All three are AEAD; the hash in the
    name is the handshake hash used by the key schedule. }
  TLS13CipherAES128GCMSHA256 = $1301;         { TLS_AES_128_GCM_SHA256 }
  TLS13CipherAES256GCMSHA384 = $1302;         { TLS_AES_256_GCM_SHA384 }
  TLS13CipherChaCha20Poly1305SHA256 = $1303;  { TLS_CHACHA20_POLY1305_SHA256 }

  { Handshake message types (RFC 8446, 4 and B.3). Only the messages used
    by this client (or recognized for diagnostics) are listed; the numeric
    values match the enum in tls.tls12. }
  TLS13HelloRequest = 0;
  TLS13ClientHello = 1;
  TLS13ServerHello = 2;
  TLS13NewSessionTicket = 4;
  TLS13EndOfEarlyData = 5;
  TLS13EncryptedExtensions = 8;
  TLS13Certificate = 11;
  TLS13CertificateRequest = 13;
  TLS13CertificateVerify = 15;
  TLS13Finished = 20;
  TLS13KeyUpdate = 24;
  TLS13MessageHash = 254;

  { Extension identifiers (RFC 8446, 4.2 and B.3.1..B.3.4). }
  TLS13ExtServerName = 0;                { server_name }
  TLS13ExtMaxFragmentLength = 1;         { max_fragment_length }
  TLS13ExtStatusRequest = 5;             { status_request }
  TLS13ExtSupportedGroups = 10;          { supported_groups }
  TLS13ExtSignatureAlgorithms = 13;      { signature_algorithms }
  TLS13ExtUseSRTP = 14;                  { use_srtp }
  TLS13ExtHeartbeat = 15;                { heartbeat }
  TLS13ExtALPN = 16;                     { application_layer_protocol_negotiation }
  TLS13ExtSignedCertificateTimestamp = 18; { signed_certificate_timestamp }
  TLS13ExtClientCertificateType = 19;    { client_certificate_type }
  TLS13ExtServerCertificateType = 20;    { server_certificate_type }
  TLS13ExtPadding = 21;                  { padding }
  TLS13ExtPreSharedKey = 41;             { pre_shared_key }
  TLS13ExtEarlyData = 42;                { early_data }
  TLS13ExtSupportedVersions = 43;        { supported_versions }
  TLS13ExtCookie = 44;                   { cookie }
  TLS13ExtPskKeyExchangeModes = 45;      { psk_key_exchange_modes }
  TLS13ExtCertificateAuthorities = 47;   { certificate_authorities }
  TLS13ExtOidFilters = 48;               { oid_filters }
  TLS13ExtPostHandshakeAuth = 49;        { post_handshake_auth }
  TLS13ExtSignatureAlgorithmsCert = 50;  { signature_algorithms_cert }
  TLS13ExtKeyShare = 51;                 { key_share }

  { PSK key exchange modes (RFC 8446, 4.2.9). Recognized so that an
    unexpected mode can be rejected explicitly. }
  TLS13PskKe = 0;      { psk_ke }
  TLS13PskDheKe = 1;   { psk_dhe_ke }

  { Legacy record content types (RFC 8446, 5.1): in TLS 1.3 the record
    type lives in the inner plaintext; the outer type is one of these. }
  TLS13ContentChangeCipherSpec = 20;
  TLS13ContentAlert = 21;
  TLS13ContentHandshake = 22;
  TLS13ContentApplicationData = 23;

{--- key_share: ECDHE on P-256/P-384 (RFC 8446, 4.2.8) ------------------- }

const
  { Named groups (RFC 8446, B.3.1.4 and the TLS Supported Groups registry).
    Only the two NIST curves are implemented; X25519 is recognized so that
    an offered or negotiated group can be rejected with a clear error
    instead of being mistaken for another one. }
  TLS13GroupSecp256r1 = 23;   { 0x0017 }
  TLS13GroupSecp384r1 = 24;   { 0x0018 }
  TLS13GroupX25519 = 29;      { 0x001D, recognized, not implemented }

type
  { KeyShareEntry (RFC 8446, 4.2.8.1):

      NamedGroup group;
      opaque key_exchange<1..2^16-1>;

    For P-256 and P-384 the key_exchange value is an uncompressed SEC 1
    point 0x04 || X || Y with fixed-size big-endian coordinates. }
  TTLS13KeyShareEntry = record
    Group: Word;
    KeyExchange: TBytes;
  end;

  { Ephemeral (EC)DHE key pair for one key_share. PrivateKey is owned by
    the holder and must be released with TLS13KeyShareFree; PublicKey is
    the serialized SEC 1 point that goes into key_share. }
  TTLS13KeyShare = record
    Group: Word;
    PrivateKey: TBN;
    PublicKey: TBytes;
  end;

{ True when AGroup is a named group for which this unit can generate a
  key_share (P-256, P-384). }
function TLS13GroupSupported(AGroup: Word): Boolean;

{ Generates an ephemeral ECDHE key pair for AGroup and serializes its
  public key in SEC 1 uncompressed form. Raises an exception for an
  unsupported group; on success PublicKey is non-empty and the returned
  PrivateKey must be freed with TLS13KeyShareFree. }
function TLS13KeyShareGenerate(AGroup: Word): TTLS13KeyShare;

{ Releases the private scalar held by AKeyShare. Safe to call on a
  zero-initialized record. }
procedure TLS13KeyShareFree(var AKeyShare: TTLS13KeyShare);

{ Serializes one KeyShareEntry: group || uint16 length || key_exchange.
  key_exchange must be 1..65535 bytes long. }
function TLS13EncodeKeyShareEntry(AGroup: Word;
  const AKeyExchange: TBytes): TBytes;

{ Serializes AKeyShare as a KeyShareEntry carrying its public key. }
function TLS13EncodeKeyShare(const AKeyShare: TTLS13KeyShare): TBytes;

{ Parses exactly one KeyShareEntry from AData (trailing bytes are
  rejected). Raises an exception when the entry is truncated, has an empty
  key_exchange, or declares a length that does not match the buffer. }
function TLS13ParseKeyShareEntry(const AData: TBytes): TTLS13KeyShareEntry;

{ ECDHE shared secret (RFC 8446, 7.4.2): Y = d * Q_peer, the secret is the
  X coordinate of Y encoded big-endian and padded to the field size of the
  group (32 bytes for P-256, 48 for P-384). APeerKeyExchange is the raw
  key_exchange value of the peer's KeyShareEntry.

  The peer point is rejected unless it is an uncompressed point of exactly
  the right length that lies on the negotiated curve and the resulting
  point is not the identity (invalid-curve / small-subgroup protection);
  every violation raises an exception. }
function TLS13KeyShareSecret(const AKeyShare: TTLS13KeyShare;
  const APeerKeyExchange: TBytes): TBytes;

{--- ClientHello (RFC 8446, 4.1.2) --------------------------------------- }

const
  { ClientHello random: 32 bytes (RFC 8446, 4.1.2). }
  TLS13ClientRandomLen = 32;
  { legacy_session_id length used in compatibility mode (RFC 8446, D.4):
    32 random bytes echoed by the server. }
  TLS13CompatSessionIDLen = 32;

type
  { One ClientHello key_share offer: the KeyShareEntry that goes on the
    wire (group and public key_exchange) together with the ephemeral key
    pair whose private scalar stays on the client side and is needed later
    by TLS13KeyShareSecret. }
  TTLS13KeyShareOffer = record
    Entry: TTLS13KeyShareEntry;
    KeyShare: TTLS13KeyShare;
  end;
  TTLS13KeyShareOffers = array of TTLS13KeyShareOffer;

  { Payload of the key_share extension:
      KeyShareEntry client_shares<0..2^16-1>. }
  TTLS13KeyShareEntries = array of TTLS13KeyShareEntry;

  { ClientHello build options. Empty CipherSuites, SupportedGroups and
    SignatureSchemes are replaced by the TLS13Default* lists; ClientRandom
    and LegacySessionID are generated when nil. KeyShareOffers must be
    generated beforehand with TLS13GenerateKeyShareOffers; the array and
    the private keys it holds stay owned by the caller. }
  TTLS13ClientHelloOptions = record
    ServerName: string;                     { SNI, empty — not sent }
    ClientRandom: TBytes;                   { nil — 32 random bytes }
    LegacySessionID: TBytes;                { nil — per CompatibilityMode }
    CipherSuites: TTLSCipherSuites;         { nil — TLS13DefaultCipherSuites }
    SupportedGroups: TTLSNamedGroups;       { nil — TLS13DefaultSupportedGroups }
    SignatureSchemes: TTLSSignatureSchemes; { nil — TLS13DefaultSignatureSchemes }
    KeyShareOffers: TTLS13KeyShareOffers;   { at least one offer is required }
    CompatibilityMode: Boolean;             { non-empty legacy_session_id }
    PskKeyExchangeModes: Boolean;           { psk_key_exchange_modes ext }
  end;

{ Whether ASuite is one of the three AEAD suites of TLS 1.3
  (RFC 8446, B.4) that this client supports. }
function TLS13CipherSuiteSupported(ASuite: TTLSCipherSuite): Boolean;

{ The three AEAD suites of RFC 8446, B.4, in the client's preference
  order: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
  TLS_CHACHA20_POLY1305_SHA256. }
function TLS13DefaultCipherSuites: TTLSCipherSuites;

{ Groups this client can generate a key_share for: secp256r1 and
  secp384r1. }
function TLS13DefaultSupportedGroups: TTLSNamedGroups;

{ Signature schemes this client can verify: ecdsa_secp256r1_sha256,
  ecdsa_secp384r1_sha384 and rsa_pss_rsae_sha256. Advertising only what
  can be checked keeps the server from selecting an unusable scheme. }
function TLS13DefaultSignatureSchemes: TTLSSignatureSchemes;

{ True when AScheme is a signature scheme this client can actually
  verify: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 or
  rsa_pss_rsae_sha256. Everything else — RSA PKCS#1 v1.5, Ed25519,
  SHA-1-based and unknown values — is never advertised, so a peer cannot
  select it and leave the handshake half-way. }
function TLS13SignatureSchemeSupported(AScheme: TTLSSignatureScheme): Boolean;

{ Default options: no SNI, no key shares (generate them with
  TLS13GenerateKeyShareOffers), default suites/groups/schemes,
  compatibility mode on, psk_key_exchange_modes off. }
function DefaultTLS13ClientHelloOptions: TTLS13ClientHelloOptions;

{ Options for AServerName with a fresh random and one generated key share
  per default group. AClientRandom may be nil. The caller owns
  KeyShareOffers and must release it with TLS13KeyShareOffersFree. }
function BuildTLS13ClientHelloOptions(const AServerName: string;
  const AClientRandom: TBytes): TTLS13ClientHelloOptions;

{ Generates one ephemeral (EC)DHE key share per group of AGroups. Every
  group is validated first, so an unsupported one is rejected before any
  key material is created. The offers own their private keys; release
  them with TLS13KeyShareOffersFree. }
function TLS13GenerateKeyShareOffers(
  const AGroups: TTLSNamedGroups): TTLS13KeyShareOffers;

{ Releases the private keys held by AOffers and empties the array. Safe to
  call more than once. }
procedure TLS13KeyShareOffersFree(var AOffers: TTLS13KeyShareOffers);

{ KeyShareEntry list (group + public key_exchange) in wire order. }
function TLS13KeyShareEntries(
  const AOffers: TTLS13KeyShareOffers): TTLS13KeyShareEntries;

{ key_share (RFC 8446, 4.2.8) for a ClientHello:

    KeyShareClientHello: opaque client_shares<0..2^16-1>;

  each entry being group(2) || uint16 length || key_exchange. An empty
  list is part of the grammar and serializes to two zero bytes. }
function EncodeTLS13KeyShareExtension(
  const AEntries: TTLS13KeyShareEntries): TTLSExtension;

{ supported_versions (RFC 8446, 4.2.1) for a ClientHello:

    opaque versions<2..254>;   // one byte list length, then uint16 values

  this client offers exactly 0x0304. }
function EncodeTLS13SupportedVersionsExtension: TTLSExtension;

{ psk_key_exchange_modes (RFC 8446, 4.2.9):

    opaque ke_modes<1..255>;   // one byte list length, then byte values

  with the single mode psk_dhe_ke (0x01). Sent only on request, because
  TLS 1.3 defines the extension for PSK handshakes. }
function EncodeTLS13PskKeyExchangeModesExtension: TTLSExtension;

{ Extension list of a TLS 1.3 ClientHello (RFC 8446, 4.1.2): server_name
  (when ServerName is not empty), supported_groups,
  signature_algorithms, supported_versions, key_share and, on request,
  psk_key_exchange_modes. }
function BuildTLS13ClientHelloExtensions(
  const AOptions: TTLS13ClientHelloOptions): TTLSExtensions;

{ ClientHello body (RFC 8446, 4.1.2):

    ProtocolVersion legacy_version = 0x0303;
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;   // one null byte
    Extension extensions<8..2^16-1>;

  Raises an exception when KeyShareOffers is empty, a field length does
  not match the grammar, an offer is not covered by supported_groups, or
  a cipher suite is unsupported. }
function BuildTLS13ClientHelloBody(
  const AOptions: TTLS13ClientHelloOptions): TBytes;

{ Full ClientHello handshake message (header + body). }
function BuildTLS13ClientHello(
  const AOptions: TTLS13ClientHelloOptions): TBytes;

{ Sends a ClientHello to the transport in one or more records. The record
  version defaults to 0x0303; RFC 8446, 5.1 also allows 0x0301 for the
  first ClientHello. }
procedure WriteTLS13ClientHello(ATransport: ITLSTransport;
  const AOptions: TTLS13ClientHelloOptions;
  AVersion: Word = TLS13LegacyVersion);

{--- ServerHello (RFC 8446, 4.1.3) --------------------------------------- }

{ Random value that marks a HelloRetryRequest instead of a real
  ServerHello (RFC 8446, 4.1.3):

    CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
    C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C

  This client does not implement a second ClientHello, so an HRR must be
  rejected explicitly rather than mistaken for an accepted ServerHello. }
const
  TLS13HelloRetryRequestRandom: array[0..31] of Byte = (
    $CF, $21, $AD, $74, $E5, $9A, $61, $11,
    $BE, $1D, $8C, $02, $1E, $65, $B8, $91,
    $C2, $A2, $11, $16, $7A, $BB, $8C, $5E,
    $07, $9E, $09, $E2, $C8, $A8, $33, $9C);

type
  { Parsed ServerHello (RFC 8446, 4.1.3):

      ProtocolVersion legacy_version = 0x0303;
      Random random;
      opaque legacy_session_id_echo<0..32>;
      CipherSuite cipher_suite;
      uint8 legacy_compression_method = 0;
      Extension extensions<6..2^16-1>;

    SupportedVersion and KeyShare come from the mandatory
    supported_versions and key_share extensions. A HelloRetryRequest
    never yields a value: it is recognized by its sentinel random and
    rejected with ETLS13Error. }
  TTLS13ServerHello = record
    LegacyVersion: Word;              { must be 0x0303 }
    Random: TBytes;                   { 32 bytes }
    LegacySessionIDEcho: TBytes;      { 0..32 bytes }
    CipherSuite: TTLSCipherSuite;     { one of the TLS 1.3 AEAD suites }
    LegacyCompressionMethod: Byte;    { must be 0 }
    Extensions: TTLSExtensions;
    SupportedVersion: Word;           { selected_version, must be 0x0304 }
    HasKeyShare: Boolean;
    KeyShare: TTLS13KeyShareEntry;    { server_share }
  end;

{ True when ARandom is the HelloRetryRequest sentinel value (RFC 8446,
  4.1.3) that a server uses in place of a real random. }
function TLS13IsHelloRetryRequest(const ARandom: TBytes): Boolean;

{ Parses the ServerHello body (the handshake header is not included).

  Raises ETLS13Error when the body is truncated or violates the grammar,
  when the random is the HelloRetryRequest sentinel (HRR is not
  supported), when legacy_version is not 0x0303, when the cipher suite is
  not a supported TLS 1.3 AEAD suite, when legacy_compression_method is
  not zero, when the supported_versions extension is missing or does not
  select TLS 1.3, when the key_share extension is missing, or when the
  server selects a group this client cannot handle. }
function ParseTLS13ServerHello(const AData: TBytes): TTLS13ServerHello;

{ Same, but also checks that legacy_session_id_echo equals the
  legacy_session_id that the client sent in its ClientHello
  (RFC 8446, 4.1.3). }
function ParseTLS13ServerHello(const AData: TBytes;
  const ALegacySessionID: TBytes): TTLS13ServerHello; overload;

{ Parses a handshake message, requiring it to be a ServerHello
  (htServerHello) with a well-formed body. }
function ParseTLS13ServerHelloMessage(
  const AMsg: TTLSHandshakeMessage): TTLS13ServerHello;

{--- EncryptedExtensions (RFC 8446, 4.3.1) ------------------------------- }

type
  { Parsed EncryptedExtensions (RFC 8446, 4.3.1). The body carries one

      Extension extensions<0..2^16-1>;

    vector. This is the first message the server protects with the
    handshake traffic keys (see the record layer section below). An empty
    extension list is legal and is encoded as one zero uint16. Extensions
    that RFC 8446 defines for other handshake messages only, or that
    acknowledge a capability this client never offers (PSK resumption,
    0-RTT, a HelloRetryRequest cookie), are rejected with ETLS13Error
    instead of being handed back as opaque data. }
  TTLS13EncryptedExtensions = record
    Extensions: TTLSExtensions;
  end;

{ Parses the EncryptedExtensions body (the handshake header is not
  included).

  Raises ETLS13Error when the two-byte extension-list length is missing or
  does not match the bytes that follow, when an extension is malformed or
  appears twice (RFC 8446, 4.2: an extension MUST NOT appear more than
  once), or when an extension that is not valid in EncryptedExtensions is
  present. }
function ParseTLS13EncryptedExtensions(
  const AData: TBytes): TTLS13EncryptedExtensions;

{ Parses a handshake message, requiring it to be an EncryptedExtensions
  (htEncryptedExtensions) with a well-formed body. }
function ParseTLS13EncryptedExtensionsMessage(
  const AMsg: TTLSHandshakeMessage): TTLS13EncryptedExtensions;

{--- Certificate (RFC 8446, 4.4.2) --------------------------------------- }

type
  { One CertificateEntry of a TLS 1.3 Certificate message (RFC 8446,
    4.4.2). For certificate_type X509 it holds one DER certificate

      opaque cert_data<1..2^24-1>;
      Extension extensions<0..2^16-1>;

    (the RawPublicKey variant is not used by this client). The entry's
    extension vector is kept for the caller (OCSP status_request,
    signed_certificate_timestamp) but is not interpreted here. }
  TTLS13CertificateEntry = record
    Certificate: TBytes;        { DER-encoded X.509 certificate }
    Extensions: TTLSExtensions; { possibly empty, never nil on success }
  end;
  TTLS13CertificateEntries = array of TTLS13CertificateEntry;

  { Parsed Certificate message body (RFC 8446, 4.4.2):

      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;

    Entries are ordered from the leaf (index 0) to the root.
    RequestContext is the certificate_request_context; it is always empty
    in the 1-RTT handshake, the only flow this client implements. }
  TTLS13Certificate = record
    RequestContext: TBytes;
    Entries: TTLS13CertificateEntries;
  end;

{ Parses the Certificate body (the handshake header is not included):
  certificate_request_context(1 + n) || certificate_list(3), where each
  entry is cert_data(3 + n) || extensions(2 + n).

  Raises ETLS13Error when the body is truncated, when a length prefix
  does not match the bytes that follow, when certificate_list is empty
  (RFC 8446, 4.4.2: the server MUST NOT send an empty list), when
  cert_data is empty, when certificate_request_context is non-empty (this
  client never answers a CertificateRequest, so a non-empty context cannot
  belong to the 1-RTT server flight), or when an entry carries the same
  extension twice (RFC 8446, 4.2). }
function ParseTLS13Certificate(const AData: TBytes): TTLS13Certificate;

{ Parses a handshake message, requiring it to be a Certificate
  (htCertificate) with a well-formed body. }
function ParseTLS13CertificateMessage(
  const AMsg: TTLSHandshakeMessage): TTLS13Certificate;

{ Builds a TTLS12CertChain (leaf at index 0) from a parsed TLS 1.3
  Certificate message. The TLS 1.3 certificate_list has the same order and
  meaning as the TLS 1.2 one, so the shared chain builder and verifier of
  tls.tls12 are reused instead of duplicating X.509 parsing and path
  building here. A cert_data that is not a well-formed DER X.509
  certificate is rejected with ETLS13Error. The caller owns the returned
  chain. }
function TLS13CertificateChain(
  const ACertificate: TTLS13Certificate): TTLS12CertChain;

{ Verifies the server certificate chain of a TLS 1.3 Certificate message
  against ATrustStore (RFC 8446, 4.4.2.2). The leaf must be signed by a
  trusted root, possibly via intermediate certificates carried in the
  message itself; validity periods are checked against ANow (0 = now) with
  at most AHops intermediate certificates. A self-signed leaf that does not
  match a trusted root, an expired certificate and an untrusted issuer all
  yield OK = False with a human-readable Reason (this function never treats
  an untrusted chain as valid). A nil store verifies structure only, so
  callers that require trust must pass a non-nil ATrustStore. OCSP and SCT
  data from the entry extensions is not consulted. }
function VerifyTLS13Certificate(const ACertificate: TTLS13Certificate;
  const ATrustStore: TCertStore; AHops: LongInt = 8;
  ANow: TDateTime = 0): TVerifyResult;

{ Same, but takes the raw Certificate handshake message (parses it first;
  a malformed body is rejected with ETLS13Error). }
function VerifyTLS13CertificateMessage(const AMsg: TTLSHandshakeMessage;
  const ATrustStore: TCertStore; AHops: LongInt = 8;
  ANow: TDateTime = 0): TVerifyResult;

{ Verifies the chain and raises ETLS13Error when it does not chain to
  ATrustStore (Reason is included in the message). }
procedure CheckTLS13Certificate(const ACertificate: TTLS13Certificate;
  const ATrustStore: TCertStore; AHops: LongInt = 8;
  ANow: TDateTime = 0);

{--- CertificateVerify (RFC 8446, 4.4.3) --------------------------------- }

const
  { Context strings of the CertificateVerify signature (RFC 8446, 4.4.3).
    The server and the client use a different string, so a signature made
    for one role can never be replayed in the other. }
  TLS13ContextStringServerCertificateVerify =
    'TLS 1.3, server CertificateVerify';
  TLS13ContextStringClientCertificateVerify =
    'TLS 1.3, client CertificateVerify';

{ The content signed by CertificateVerify (RFC 8446, 4.4.3):

    0x20 repeated 64 times || context string || 0x00 ||
        Transcript-Hash(Handshake Context, Certificate)

  AContextString is one of the TLS13ContextString* constants above (passed
  verbatim, it already starts with "TLS 1.3, "). ATranscriptHash must
  already be Transcript-Hash(Handshake Context, Certificate) — callers that
  keep the running handshake hash avoid re-hashing here. Its length is not
  constrained by this function; the signature verifier decides whether it
  matches the hash of the negotiated cipher suite. An empty context string
  raises ETLS13Error, because a signature over just the padding and the
  transcript hash would not be bound to its purpose. }
function TLS13CertificateVerifyContent(const AContextString: AnsiString;
  const ATranscriptHash: TBytes): TBytes;

{ Same, but hashes the raw handshake transcript first (see
  TLS13TranscriptHash). }
function TLS13CertificateVerifyContentFromTranscript(
  const AContextString: AnsiString; AHash: THashKind;
  const ATranscript: TBytes): TBytes;

{ Convenience wrappers for the two roles of RFC 8446, 4.4.3: the server
  signs with TLS13ContextStringServerCertificateVerify, the client with
  TLS13ContextStringClientCertificateVerify. }
function TLS13ServerCertificateVerifyContent(AHash: THashKind;
  const ATranscriptHash: TBytes): TBytes;
function TLS13ClientCertificateVerifyContent(AHash: THashKind;
  const ATranscriptHash: TBytes): TBytes;

{ Curves of the ECDSA signature schemes this client can verify
  (RFC 8446, 4.2.3):

    ecdsa_secp256r1_sha256 -> P-256 (the hash is SHA-256),
    ecdsa_secp384r1_sha384 -> P-384 (the hash is SHA-384).

  Returns a freshly allocated TECCurve that the caller must Free, or nil
  for every other scheme (RSA-PSS, Ed25519, unknown). A nil result tells
  the caller that the scheme does not belong to the ECDSA verification
  path, so an RSA or Ed25519 signature can never be checked as if it were
  an ECDSA one. }
function TLS13ECDSASignatureSchemeCurve(
  AScheme: TTLSSignatureScheme): TECCurve;

{ Verifies the CertificateVerify signature ASignature of AScheme over
  AContent with the public key of the leaf certificate ACert (RFC 8446,
  4.4.3). AContent is the content built by TLS13CertificateVerifyContent,
  ASignature is the DER-encoded ECDSA-Sig-Value from CertificateVerify.

  Returns True only when the scheme is one of the two ECDSA schemes above,
  the certificate carries an EC public key on exactly the curve named by
  the scheme, and the signature verifies. Returns False for everything
  else: a nil certificate, an empty content or signature, a non-EC or
  mismatched key, a malformed DER signature or an invalid signature. In
  particular the hash is fixed by the scheme (SHA-256 for P-256, SHA-384
  for P-384), so a signature made with the other curve's hash is never
  accepted. RSA-PSS is handled by the dedicated function added for it. }
function VerifyTLS13ECDSASignature(const ACert: TX509Cert;
  AScheme: TTLSSignatureScheme; const AContent, ASignature: TBytes): Boolean;

{ Verifies an RSA-PSS-SHA256 CertificateVerify signature (RFC 8446, 4.4.3;
  RSASSA-PSS in RFC 8017, 8.1). rsa_pss_rsae_sha256 is the only RSA scheme
  that TLS 1.3 permits in CertificateVerify (RFC 8446, 4.2.3): the legacy
  rsa_pkcs1_* schemes are rejected here with False rather than being
  accepted under the TLS 1.2 rules.

  AContent is the content built by TLS13CertificateVerifyContent; ASignature
  is the raw big-endian RSA signature from CertificateVerify (modulus-sized,
  no DER wrapper). Returns True only when the scheme is
  rsa_pss_rsae_sha256, the certificate carries an RSA public key and the PSS
  signature over SHA-256(AContent) verifies. Returns False for everything
  else: a nil certificate, an empty content or signature, a non-RSA key, a
  different scheme or an invalid signature. The salt length is fixed to the
  hash length (32), as RFC 8017 prescribes by default. }
function VerifyTLS13RSAPSSSignature(const ACert: TX509Cert;
  AScheme: TTLSSignatureScheme; const AContent, ASignature: TBytes): Boolean;

{--- key schedule (RFC 8446, 7.1) ---------------------------------------- }

{ Maps a TLS 1.3 cipher suite onto the hash used by its key schedule:
  0x1301 TLS_AES_128_GCM_SHA256        -> SHA-256,
  0x1302 TLS_AES_256_GCM_SHA384        -> SHA-384,
  0x1303 TLS_CHACHA20_POLY1305_SHA256  -> SHA-256.
  Any other value raises ETLS13Error, so an unsupported cipher suite never
  silently picks a hash. }
function TLS13CipherSuiteHashKind(ASuite: TTLSCipherSuite): THashKind;

{ Transcript-Hash(Messages) (RFC 8446, 4.4.1): the handshake hash over the
  concatenated handshake messages, SHA-256 or SHA-384 for the TLS 1.3
  cipher suites. An empty transcript hashes to Hash(""). }
function TLS13TranscriptHash(AHash: THashKind;
  const ATranscript: TBytes): TBytes;

{ Derive-Secret(Secret, Label, Messages) (RFC 8446, 7.1):

    Derive-Secret(., Label, Msgs) =
        HKDF-Expand-Label(., Label, Transcript-Hash(Msgs), Hash.length)

  ATranscriptHash must already be Transcript-Hash(Msgs); callers that keep
  the running handshake hash avoid re-hashing through this entry point.
  ALabel is given without the "tls13 " prefix added by
  HKDF-Expand-Label. }
function TLS13DeriveSecretFromHash(AHash: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const ATranscriptHash: TBytes): TBytes;

{ Same, but hashes the raw transcript first. An empty ATranscript yields
  the Hash("") context used by the "derived" stage of the schedule. }
function TLS13DeriveSecret(AHash: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;

{ Labels used by the TLS 1.3 key schedule (RFC 8446, 7.1). They are passed
  to the derivation functions without the "tls13 " prefix. }
const
  TLS13LabelDerived = 'derived';
  TLS13LabelClientHandshakeTraffic = 'c hs traffic';
  TLS13LabelServerHandshakeTraffic = 's hs traffic';
  TLS13LabelClientApplicationTraffic = 'c ap traffic';
  TLS13LabelServerApplicationTraffic = 's ap traffic';
  TLS13LabelExporterMaster = 'exp master';
  TLS13LabelResumptionMaster = 'res master';

{ PSK -> HKDF-Extract = Early Secret (RFC 8446, 7.1). The salt is HashLen
  zero bytes; APSK is the pre-shared key, or an empty string for a full
  1-RTT handshake without a PSK, in which case the IKM is HashLen zero
  bytes ("if no PSK is being used, then the value is a string of
  Hash.length zeros"). }
function TLS13EarlySecret(AHash: THashKind; const APSK: TBytes): TBytes;

{ Derive-Secret(Secret, "derived", "") — the stage separating the early,
  handshake and master secrets in the schedule. }
function TLS13DerivedSecret(AHash: THashKind; const ASecret: TBytes): TBytes;

{ (EC)DHE -> HKDF-Extract = Handshake Secret: HKDF-Extract over the
  "derived" stage of the early secret and the (EC)DHE shared secret. }
function TLS13HandshakeSecret(AHash: THashKind; const AEarlySecret,
  ADHESharedSecret: TBytes): TBytes;

{ 0 -> HKDF-Extract = Master Secret: HKDF-Extract over the "derived" stage
  of the handshake secret and HashLen zero bytes. }
function TLS13MasterSecret(AHash: THashKind;
  const AHandshakeSecret: TBytes): TBytes;

{ Traffic secrets (RFC 8446, 7.1). ATranscript is the transcript the given
  secret is derived from: ClientHello..ServerHello for the handshake
  traffic secrets, ClientHello..server Finished for the application
  traffic secrets. }
function TLS13ClientHandshakeTrafficSecret(AHash: THashKind;
  const AHandshakeSecret, ATranscript: TBytes): TBytes;
function TLS13ServerHandshakeTrafficSecret(AHash: THashKind;
  const AHandshakeSecret, ATranscript: TBytes): TBytes;
function TLS13ClientApplicationTrafficSecret(AHash: THashKind;
  const AMasterSecret, ATranscript: TBytes): TBytes;
function TLS13ServerApplicationTrafficSecret(AHash: THashKind;
  const AMasterSecret, ATranscript: TBytes): TBytes;

type
  { All secrets of one TLS 1.3 handshake (RFC 8446, 7.1). Every secret is
    HashLen bytes long; HashKind names the handshake hash the schedule was
    run with. }
  TTLS13KeySchedule = record
    HashKind: THashKind;
    HashLen: Integer;
    EarlySecret: TBytes;
    HandshakeSecret: TBytes;
    MasterSecret: TBytes;
    ClientHandshakeTrafficSecret: TBytes;
    ServerHandshakeTrafficSecret: TBytes;
    ClientApplicationTrafficSecret: TBytes;
    ServerApplicationTrafficSecret: TBytes;
  end;

{ Runs the key schedule up to the application traffic secrets. APSK is the
  pre-shared key (empty for a full handshake), ADHE the (EC)DHE shared
  secret, AHelloTranscript the transcript through ServerHello and
  AServerFinishedTranscript the transcript through the server's Finished. }
function TLS13DeriveKeySchedule(AHash: THashKind; const APSK, ADHE: TBytes;
  const AHelloTranscript, AServerFinishedTranscript: TBytes)
  : TTLS13KeySchedule;

{--- record layer (RFC 8446, 5) ------------------------------------------ }

const
  { Outer (opaque) content type of every protected TLS 1.3 record
    (RFC 8446, 5.2): the real content type lives in the inner plaintext,
    so protected records always use application_data. }
  TLS13RecordOpaqueType = TLS13ContentApplicationData;

  { legacy_record_version of a TLS 1.3 record (RFC 8446, 5.1): the value
    0x0303 is used for every record, including the initial ClientHello. }
  TLS13RecordLegacyVersion = $0303;

  { Length of the AEAD tag appended to every protected record. TLS 1.3
    has no explicit per-record nonce (RFC 8446, 5.2). }
  TLS13RecordTagLength = 16;

  { Length of the write IV and of the per-record nonce (RFC 8446, 5.3):
    12 bytes for every TLS 1.3 cipher suite (AES-GCM, ChaCha20-Poly1305). }
  TLS13RecordIVLen = 12;

  { Maximum length of the serialized inner plaintext (RFC 8446, 5.1, 5.2):
    TLSCiphertext.length is at most 2^14 + 256 bytes and covers the inner
    plaintext plus the AEAD tag, so the inner plaintext itself is at most
    (2^14 + 256 - TLS13RecordTagLength) bytes. }
  TLS13InnerPlaintextMaxLength = (1 shl 14) + 256 - TLS13RecordTagLength;

  { Labels of the record protection keys derived from a traffic secret
    (RFC 8446, 7.3):

      key = HKDF-Expand-Label(Secret, "key", "", key_length)
      iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)

    They are passed to HKDFExpandLabel without the "tls13 " prefix. }
  TLS13LabelWriteKey = 'key';
  TLS13LabelWriteIV = 'iv';

type
  { AEAD key and write IV of one TLS 1.3 traffic secret (RFC 8446, 7.3),
    as used to protect and unprotect records of that direction: Key is the
    key_length-byte AEAD key, IV the 12-byte iv. }
  TTLS13RecordKeys = record
    Key: TBytes;
    IV: TBytes;
  end;

{ AEAD mode of a TLS 1.3 cipher suite: 0x1301 -> AES-128-GCM,
  0x1302 -> AES-256-GCM, 0x1303 -> ChaCha20-Poly1305. Any other suite
  raises ETLS13Error: TLS 1.3 allows only AEAD suites and this client
  implements exactly these three. }
function TLS13CipherSuiteAEADMode(ASuite: TTLSCipherSuite): TTLSAEADMode;

{ AEAD key length (key_length, RFC 8446, 5.3) of a TLS 1.3 cipher suite:
  16 bytes for TLS_AES_128_GCM_SHA256, 32 bytes for
  TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256. Any other
  suite raises ETLS13Error. }
function TLS13CipherSuiteKeyLength(ASuite: TTLSCipherSuite): Integer;

{ Record protection keys of one traffic secret (RFC 8446, 7.3):
    key = HKDF-Expand-Label(Secret, "key", "", key_length)
    iv  = HKDF-Expand-Label(Secret, "iv",  "", 12)
  ASecret is the client or server traffic secret of the handshake or
  application phase and must be HashLen bytes long. The suite selects both
  the AEAD mode and the key length; AHash is the handshake hash, which is
  also the one of the suite (TLS13CipherSuiteHashKind). }
function TLS13DeriveRecordKeys(AHash: THashKind; ASuite: TTLSCipherSuite;
  const ASecret: TBytes): TTLS13RecordKeys;

{ Per-record nonce (RFC 8446, 5.3):

    nonce = iv XOR seq_num

  where seq_num is the 64-bit record sequence number encoded big-endian
  and left-padded with zero bytes to the size of the write IV. The
  sequence number starts at zero for every key set and is never reused.
  AIV must be TLS13RecordIVLen bytes long; ASeqNum may be any 64-bit
  value. }
function TLS13RecordNonce(const AIV: TBytes; ASeqNum: QWord): TBytes;

{ Additional data of a protected TLS 1.3 record (RFC 8446, 5.2):

    additional_data = opaque_type(1) || legacy_record_version(2) ||
                      TLSCiphertext.length(2)

  That is exactly the 5-byte record header of the record being protected,
  with ACiphertextLength = length of the encrypted inner plaintext plus
  the AEAD tag. ACiphertextLength must fit into a uint16. }
function TLS13RecordAdditionalData(ACiphertextLength: Integer): TBytes;

{ Protects one record: encrypts APlain — the already serialized inner
  plaintext — with the AEAD of the suite and returns the record fragment
  ciphertext || tag (RFC 8446, 5.2). The nonce comes from AIV and
  ASeqNum, the AAD is the 5-byte header built for the resulting ciphertext
  length. AKey must be the key_length-byte key of APlain's key set. }
function TLS13ProtectRecordFragment(ASuite: TTLSCipherSuite;
  const AKey, AIV: TBytes; ASeqNum: QWord;
  const APlain: TBytes): TBytes;

{ Opposite of TLS13ProtectRecordFragment: verifies the AEAD tag and
  returns the inner plaintext of AFragment (ciphertext || tag). A bad tag,
  a missing tag or a malformed fragment raises ETLS13Error instead of
  returning partial data — an authentication failure must abort the
  connection (RFC 8446, 5.2). }
function TLS13UnprotectRecordFragment(ASuite: TTLSCipherSuite;
  const AKey, AIV: TBytes; ASeqNum: QWord;
  const AFragment: TBytes): TBytes;

{ Serializes a TLS 1.3 inner plaintext (RFC 8446, 5.2):
   TLSInnerPlaintext = content || type || zeros[length_of_padding]

  AContent is the record payload, AContentType its legacy content type and
  APadding the number of zero bytes appended after the type. Only the three
  protected types (alert, handshake, application_data) are accepted: a
  change_cipher_spec must never be protected (RFC 8446, 5). The result is
  content || type || 0^APadding and must fit TLS13InnerPlaintextMaxLength. }
function TLS13EncodeInnerPlaintext(AContentType: Byte;
  const AContent: TBytes; APadding: Integer = 0): TBytes;

{ Parses a decrypted TLS 1.3 inner plaintext (RFC 8446, 5.2): the trailing
  zero bytes are padding, the last non-zero byte is the real content type and
  everything before it is the content. Returns the number of padding bytes
  and sets AContentType and AContent accordingly. An empty record, a record
  that is all padding, a change_cipher_spec (which must stay unprotected,
  RFC 8446, 5) or any unknown content type raises ETLS13Error. }
function TLS13DecodeInnerPlaintext(const APlain: TBytes;
  out AContentType: Byte; out AContent: TBytes): Integer;

{ Length of the serialized inner plaintext for a content of AContentLength
  bytes with APadding zero bytes (RFC 8446, 5.2):
  AContentLength + 1 (the content type) + APadding. A negative length, a
  negative padding or a total beyond TLS13InnerPlaintextMaxLength raises
  ETLS13Error. }
function TLS13InnerPlaintextLength(AContentLength, APadding: Integer): Integer;

{ A TLS 1.3 peer may inject a bare ChangeCipherSpec record for middlebox
  compatibility (RFC 8446, 5): it carries the single byte 0x01 and must be
  dropped without further processing. True when AType is ctChangeCipherSpec
  and AFragment is exactly the single byte 0x01. }
function TLS13IsLegacyChangeCipherSpec(AType: TTLSContentType;
  const AFragment: TBytes): Boolean;

{ Validates the body of a legacy ChangeCipherSpec record: exactly one byte
  0x01. Anything else raises ETLS13Error — a malformed CCS is not the
  compatibility signal and must abort the handshake. }
procedure TLS13CheckLegacyChangeCipherSpec(const AFragment: TBytes);

{--- Finished (RFC 8446, 4.4.4) ------------------------------------------ }

const
  { Label of the Finished key derivation (RFC 8446, 4.4.4):

      finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)

    It is passed to HKDFExpandLabel without the "tls13 " prefix. }
  TLS13LabelFinished = 'finished';

{ Finished key of one handshake traffic secret (RFC 8446, 4.4.4):
  finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length).
  ABaseKey is the handshake traffic secret of the sender (the
  client_handshake_traffic_secret for the client Finished, the
  server_handshake_traffic_secret for the server Finished) and is HashLen
  bytes long; anything else raises ETLS13Error. }
function TLS13FinishedKey(AHash: THashKind; const ABaseKey: TBytes): TBytes;

{ verify_data sent in the Finished message (RFC 8446, 4.4.4):

    verify_data = HMAC(finished_key,
                       Transcript-Hash(Handshake Context, Certificate*,
                                       CertificateVerify*))

  ATranscriptHash must already be Transcript-Hash(...) — callers that keep
  the running handshake hash avoid re-hashing. ABaseKey is the sender's
  handshake traffic secret; the result is HashLen bytes long (SHA-256 ->
  32, SHA-384 -> 48), which is also the length of the Finished body. }
function TLS13VerifyDataFromHash(AHash: THashKind; const ABaseKey: TBytes;
  const ATranscriptHash: TBytes): TBytes;

{ Same, but hashes the raw handshake transcript first. }
function TLS13VerifyData(AHash: THashKind; const ABaseKey: TBytes;
  const ATranscript: TBytes): TBytes;

{ Comparison of two byte strings in constant time: the loop always walks
  the whole input and never exits early, so the running time does not
  depend on the position or the value of the first differing byte. Only
  the lengths — public values in TLS, verify_data is always HashLen bytes
  — may short-circuit to False. Used to check verify_data, which is
  secret-dependent (RFC 8446, 4.4.4). }
function TLS13ConstantTimeEquals(const A, B: TBytes): Boolean;

{ Recomputes the peer's verify_data from ABaseKey — the *peer's* handshake
  traffic secret — and compares it with AVerifyData in constant time
  (RFC 8446, 4.4.4). ATranscriptHash must be the transcript the peer
  covered. False means the Finished message must be treated as a fatal
  handshake (decryption) failure; no partial result is returned. }
function TLS13CheckVerifyDataFromHash(AHash: THashKind;
  const ABaseKey, ATranscriptHash, AVerifyData: TBytes): Boolean;

{ Same, but hashes the raw handshake transcript first. }
function TLS13CheckVerifyData(AHash: THashKind;
  const ABaseKey, ATranscript, AVerifyData: TBytes): Boolean;

{--- High-level client (RFC 8446) --------------------------------------- }

{High-level TLS 1.3 client: performs the 1-RTT handshake of RFC 8446 over
  an ITLSTransport and afterwards provides Send/Recv for application data.

  The client is single-use: one Connect() per instance. After the handshake
  completes, Send/Recv operate on the encrypted channel.

  Scope and limitations (RFC 8446, 1.2 and 4):
    - client side only, 1-RTT handshake, no 0-RTT / early data;
    - no PSK resumption: only ephemeral (EC)DHE key shares on P-256/P-384;
    - no HelloRetryRequest: the sentinel ServerHello of RFC 8446, 4.1.3 is
      rejected with ETLS13Error instead of triggering a second ClientHello;
    - certificates are mandatory: the server flight must contain Certificate
      and CertificateVerify, and client certificate authentication is
      refused;
    - only the three AEAD cipher suites of RFC 8446, B.4 are accepted; a
      server that selects anything else is rejected;
    - only the signature schemes advertised by TLS13DefaultSignatureSchemes
      can be verified (ECDSA P-256/P-384 with SHA-256/384 and RSA-PSS with
      SHA-256).

  Certificate verification: when TrustStore is set (non-nil) the server
  chain is verified against it during Connect; when it is nil the chain is
  still parsed and available through CertChain but not authenticated.

  The transport is only touched through tls.tls12.ITLSTransport, so the
  client stays testable in memory. }
type
  TTLS13Client = class
private
  FTransport: ITLSTransport;
  FOptions: TTLS13ClientHelloOptions;
  FKeyShares: TTLS13KeyShareOffers;
  FOwnsKeyShares: Boolean;
  FTrustStore: TCertStore;
  FChain: TTLS12CertChain;
  FConnected: Boolean;
  FHandshakeDone: Boolean;
  FStarted: Boolean;
  FCipherSuite: TTLSCipherSuite;
  FHashKind: THashKind;
  FHandshakeSecret: TBytes;
  FMasterSecret: TBytes;
  FClientHandshakeTrafficSecret: TBytes;
  FServerHandshakeTrafficSecret: TBytes;
  FClientApplicationTrafficSecret: TBytes;
  FServerApplicationTrafficSecret: TBytes;
  FClientHandshakeKeys: TTLS13RecordKeys;
  FServerHandshakeKeys: TTLS13RecordKeys;
  FClientApplicationKeys: TTLS13RecordKeys;
  FServerApplicationKeys: TTLS13RecordKeys;
  FClientSeq: QWord;
  FServerSeq: QWord;
  FHandshakeData: TBytes;
  FTranscript: TBytes;
  FRecvBuf: TBytes;
  FRecvPos: Integer;
  function GetHandshakeDone: Boolean;
  function GetCipherSuite: TTLSCipherSuite;
  function GetPendingBytes: LongInt;
  procedure PrepareClientHello;
  function FindKeyShare(AGroup: Word): Integer;
  procedure AppendTranscript(AType: TTLSHandshakeType;
    const ABody: TBytes);
  procedure AppendTranscriptMessage(const AMsg: TTLSHandshakeMessage);
  function HasCompleteHandshakeMessage: Boolean;
  function TakeHandshakeMessage: TTLSHandshakeMessage;
  procedure ReadPlaintextHandshakeRecord;
  procedure ReadProtectedHandshakeRecord;
  function NextProtectedHandshakeMessage: TTLSHandshakeMessage;
  procedure HandlePostHandshakeHandshake(const AData: TBytes);
  procedure DoHandshake;
public
  constructor Create;
  destructor Destroy; override;
  {Configuration; must be set before Connect. Empty fields keep their
    defaults: a fresh random and legacy_session_id, the three AEAD suites,
    P-256/P-384 and one generated key share per offered group.}
  property Options: TTLS13ClientHelloOptions read FOptions write FOptions;
  {Optional trust store for certificate verification (not owned by the
    client). nil disables chain verification.}
  property TrustStore: TCertStore read FTrustStore write FTrustStore;
  {Performs the TLS 1.3 handshake over ATransport. Raises ETLS13Error on
    any protocol, cryptographic or verification error.}
  procedure Connect(ATransport: ITLSTransport);
  {Sends application data over the encrypted channel. Must be called after
    a successful Connect.}
  procedure Send(const AData: TBytes);
  {Receives application data. Returns the number of bytes read:
    > 0 — bytes read into ABuffer;
    = 0 — connection closed by peer (close_notify or EOF);
    < 0 — error (TLSTransportError).
    Must be called after a successful Connect.}
  function Recv(var ABuffer; ACount: LongInt): LongInt;
  {Sends close_notify (encrypted) and marks the connection closed.}
  procedure Shutdown;
  {Closes the connection without sending close_notify.}
  procedure Close;
  {Whether the handshake has completed.}
  property HandshakeDone: Boolean read GetHandshakeDone;
  {Negotiated cipher suite (valid after Connect).}
  property CipherSuite: TTLSCipherSuite read GetCipherSuite;
  {Server certificate chain (owned by the client; freed in Destroy).
    nil before Connect; Count = 0 when the server sent no certificate.}
  function CertChain: TTLS12CertChain;
  {Number of decrypted application-data bytes still buffered inside the
    client (analogous to SSL_pending / BytesAvailable).}
  property PendingBytes: LongInt read GetPendingBytes;
end;

implementation

uses
  tls.aes, tls.chacha20;

{--- HKDF (RFC 5869) ----------------------------------------------------- }

{ Concatenation helper: FPC 3.2.2 does not overload "+" for TBytes. }
function BytesConcat(const A, B: TBytes): TBytes;
var
  N, M: Integer;
begin
  N := Length(A);
  M := Length(B);
  SetLength(Result, N + M);
  if N > 0 then
    Move(A[0], Result[0], N);
  if M > 0 then
    Move(B[0], Result[N], M);
end;

function TLS13HashLen(AHash: THashKind): Integer;
begin
  case AHash of
    hkSHA256: Result := 32;
    hkSHA384: Result := 48;
    hkSHA512: Result := 64;
  else
    raise ETLS13Error.Create('HKDF: unsupported hash kind');
  end;
end;

function HKDFExtract(AHash: THashKind; const Salt, IKM: TBytes): TBytes;
var
  S: TBytes;
begin
  if Length(Salt) = 0 then
  begin
    SetLength(S, TLS13HashLen(AHash));
    if Length(S) > 0 then
      FillChar(S[0], Length(S), 0);
  end
  else
    S := Salt;
  Result := THMAC.Compute(AHash, S, IKM);
end;

function HKDFExpand(AHash: THashKind; const PRK, Info: TBytes;
  ALen: Integer): TBytes;
var
  HashLen, N, I, Take, Offset: Integer;
  T, Block: TBytes;
begin
  HashLen := TLS13HashLen(AHash);
  if ALen < 0 then
    raise ETLS13Error.Create('HKDF-Expand: negative output length');
  if ALen > 255 * HashLen then
    raise ETLS13Error.Create('HKDF-Expand: output length exceeds 255*HashLen');
  if Length(PRK) < HashLen then
    raise ETLS13Error.Create('HKDF-Expand: PRK shorter than HashLen');
  SetLength(Result, ALen);
  if ALen = 0 then
    Exit;
  N := (ALen + HashLen - 1) div HashLen;
  SetLength(T, 0);
  I := 0;
  while I < N do
  begin
    Inc(I);
    { T(i) = HMAC-Hash(PRK, T(i-1) || info || byte(i)) }
    Block := BytesConcat(T, Info);
    SetLength(Block, Length(Block) + 1);
    Block[Length(Block) - 1] := Byte(I);
    T := THMAC.Compute(AHash, PRK, Block);
    Offset := (I - 1) * HashLen;
    Take := ALen - Offset;
    if Take > HashLen then
      Take := HashLen;
    Move(T[0], Result[Offset], Take);
  end;
end;

{--- HKDF-Expand-Label (RFC 8446, 7.1) ----------------------------------- }

function TLS13HkdfLabel(const ALabel: AnsiString; const AContext: TBytes;
  ALen: Integer): TBytes;
var
  Full: AnsiString;
  LabelLen, CtxLen, Offset: Integer;
begin
  if (ALen < 0) or (ALen > High(Word)) then
    raise ETLS13Error.Create(
      'HKDF-Expand-Label: output length does not fit into uint16');
  if ALabel = '' then
    raise ETLS13Error.Create('HKDF-Expand-Label: empty label');
  Full := TLS13LabelPrefix + ALabel;
  LabelLen := Length(Full);
  if LabelLen > 255 then
    raise ETLS13Error.Create('HKDF-Expand-Label: label longer than 255 bytes');
  CtxLen := Length(AContext);
  if CtxLen > 255 then
    raise ETLS13Error.Create(
      'HKDF-Expand-Label: context longer than 255 bytes');
  SetLength(Result, 2 + 1 + LabelLen + 1 + CtxLen);
  Result[0] := Byte(ALen shr 8);
  Result[1] := Byte(ALen and $FF);
  Result[2] := Byte(LabelLen);
  Move(Full[1], Result[3], LabelLen);
  Offset := 3 + LabelLen;
  Result[Offset] := Byte(CtxLen);
  if CtxLen > 0 then
    Move(AContext[0], Result[Offset + 1], CtxLen);
end;

function HKDFExpandLabel(AHash: THashKind; const Secret: TBytes;
  const ALabel: AnsiString; const AContext: TBytes; ALen: Integer): TBytes;
begin
  Result := HKDFExpand(AHash, Secret,
    TLS13HkdfLabel(ALabel, AContext, ALen), ALen);
end;

{--- key_share: ECDHE on P-256/P-384 (RFC 8446, 4.2.8) ------------------- }

{ Maps a named group onto its NIST curve. Any other group is rejected, so
  that an unsupported offer never turns into silent misbehaviour. }
function TLS13GroupCurve(AGroup: Word): TECCurve;
begin
  case AGroup of
    TLS13GroupSecp256r1: Result := CurveP256;
    TLS13GroupSecp384r1: Result := CurveP384;
  else
    raise ETLS13Error.CreateFmt(
      'key_share: unsupported named group %d (only secp256r1 and secp384r1 '
      + 'are implemented)', [AGroup]);
  end;
end;

{ Field size in bytes of the curve selected by AGroup: 32 for P-256,
  48 for P-384. }
function TLS13GroupFieldSize(AGroup: Word): Integer;
begin
  case AGroup of
    TLS13GroupSecp256r1: Result := 32;
    TLS13GroupSecp384r1: Result := 48;
  else
    raise ETLS13Error.CreateFmt('key_share: unsupported named group %d',
      [AGroup]);
  end;
end;

{ Left-pads A with zero bytes to ALen. Raises when A is already longer,
  because silently truncating key material is never acceptable. }
function PadLeftBytes(const A: TBytes; ALen: Integer): TBytes;
var
  N, Pad: Integer;
begin
  N := Length(A);
  if N > ALen then
    raise ETLS13Error.Create('key_share: value longer than the field size');
  SetLength(Result, ALen);
  Pad := ALen - N;
  if Pad > 0 then
    FillChar(Result[0], Pad, 0);
  if N > 0 then
    Move(A[0], Result[Pad], N);
end;

function TLS13GroupSupported(AGroup: Word): Boolean;
begin
  Result := (AGroup = TLS13GroupSecp256r1) or (AGroup = TLS13GroupSecp384r1);
end;

function TLS13KeyShareGenerate(AGroup: Word): TTLS13KeyShare;
var
  Curve: TECCurve;
  Pair: TECKeypair;
begin
  Result.Group := AGroup;
  Result.PrivateKey := nil;
  Result.PublicKey := nil;
  Curve := TLS13GroupCurve(AGroup);
  try
    { Fresh ephemeral scalar per handshake; GenerateKeyPair takes the
      randomness from tls.rand through tls.ec. }
    Pair := GenerateKeyPair(Curve);
    try
      Result.PrivateKey := Pair.PrivateKey.Clone;
      Result.PublicKey := EncodePoint(Curve, Pair.PublicKey);
    finally
      Pair.Free;
    end;
  finally
    Curve.Free;
  end;
end;

procedure TLS13KeyShareFree(var AKeyShare: TTLS13KeyShare);
begin
  if AKeyShare.PrivateKey <> nil then
  begin
    AKeyShare.PrivateKey.Free;
    AKeyShare.PrivateKey := nil;
  end;
  AKeyShare.PublicKey := nil;
  AKeyShare.Group := 0;
end;

function TLS13EncodeKeyShareEntry(AGroup: Word;
  const AKeyExchange: TBytes): TBytes;
var
  N: Integer;
begin
  N := Length(AKeyExchange);
  if (N < 1) or (N > High(Word)) then
    raise ETLS13Error.CreateFmt(
      'key_share: key_exchange length %d out of range 1..65535', [N]);
  SetLength(Result, 4 + N);
  Result[0] := Byte(AGroup shr 8);
  Result[1] := Byte(AGroup and $FF);
  Result[2] := Byte(N shr 8);
  Result[3] := Byte(N and $FF);
  Move(AKeyExchange[0], Result[4], N);
end;

function TLS13EncodeKeyShare(const AKeyShare: TTLS13KeyShare): TBytes;
begin
  Result := TLS13EncodeKeyShareEntry(AKeyShare.Group, AKeyShare.PublicKey);
end;

function TLS13ParseKeyShareEntry(const AData: TBytes): TTLS13KeyShareEntry;
var
  N: Integer;
begin
  Result.Group := 0;
  Result.KeyExchange := nil;
  if Length(AData) < 4 then
    raise ETLS13Error.Create('key_share: entry shorter than 4 bytes');
  Result.Group := (Word(AData[0]) shl 8) or Word(AData[1]);
  N := (Integer(AData[2]) shl 8) or Integer(AData[3]);
  if N < 1 then
    raise ETLS13Error.Create('key_share: empty key_exchange');
  if Length(AData) <> 4 + N then
    raise ETLS13Error.CreateFmt(
      'key_share: declared key_exchange length %d does not match %d bytes',
      [N, Length(AData) - 4]);
  SetLength(Result.KeyExchange, N);
  Move(AData[4], Result.KeyExchange[0], N);
end;

function TLS13KeyShareSecret(const AKeyShare: TTLS13KeyShare;
  const APeerKeyExchange: TBytes): TBytes;
var
  Curve: TECCurve;
  Peer, Secret: TECPoint;
  FieldSize: Integer;
  X: TBytes;
begin
  if AKeyShare.PrivateKey = nil then
    raise ETLS13Error.Create('key_share: key share has no private key');
  FieldSize := TLS13GroupFieldSize(AKeyShare.Group);
  if Length(APeerKeyExchange) <> 1 + 2 * FieldSize then
    raise ETLS13Error.CreateFmt(
      'key_share: key_exchange for group %d must be %d bytes, got %d',
      [AKeyShare.Group, 1 + 2 * FieldSize, Length(APeerKeyExchange)]);
  if APeerKeyExchange[0] <> $04 then
    raise ETLS13Error.Create(
      'key_share: only uncompressed (0x04) peer points are accepted');
  Curve := TLS13GroupCurve(AKeyShare.Group);
  try
    Peer := DecodePoint(Curve, APeerKeyExchange);
    try
      if Peer.Infinity then
        raise ETLS13Error.Create('key_share: peer sent the point at infinity');
      if not IsOnCurve(Curve, Peer) then
        raise ETLS13Error.Create(
          'key_share: peer key_exchange is not on the negotiated curve');
      Secret := ComputeSharedSecret(Curve, AKeyShare.PrivateKey, Peer);
      try
        if Secret.Infinity then
          raise ETLS13Error.Create(
            'key_share: shared secret is the point at infinity');
        { RFC 8446, 7.4.2: the shared secret is the X coordinate of
          d * Q_peer, encoded with the field size of the curve. }
        X := Secret.X.ToBytes(True);
        Result := PadLeftBytes(X, FieldSize);
      finally
        Secret.Free;
      end;
    finally
      Peer.Free;
    end;
  finally
    Curve.Free;
  end;
end;

{--- ClientHello (RFC 8446, 4.1.2) --------------------------------------- }

{ Byte and uint16 appenders used to assemble the ClientHello body and its
  extensions (FPC 3.2.2 does not overload "+" for TBytes). }
function TLS13BufByte(const A: TBytes; B: Byte): TBytes;
begin
  SetLength(Result, Length(A) + 1);
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  Result[Length(A)] := B;
end;

function TLS13BufWord(const A: TBytes; W: Word): TBytes;
begin
  Result := TLS13BufByte(A, Byte(W shr 8));
  Result := TLS13BufByte(Result, Byte(W and $FF));
end;

function TLS13BufBytes(const A, B: TBytes): TBytes;
begin
  Result := BytesConcat(A, B);
end;

{ Whether AGroups contains AGroup. }
function TLS13GroupInList(const AGroups: TTLSNamedGroups;
  AGroup: Word): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(AGroups) do
    if AGroups[i] = AGroup then
      Exit(True);
  Result := False;
end;

function TLS13CipherSuiteSupported(ASuite: TTLSCipherSuite): Boolean;
begin
  Result := (ASuite = TLS13CipherAES128GCMSHA256) or
    (ASuite = TLS13CipherAES256GCMSHA384) or
    (ASuite = TLS13CipherChaCha20Poly1305SHA256);
end;

function TLS13DefaultCipherSuites: TTLSCipherSuites;
begin
  SetLength(Result, 3);
  Result[0] := TLS13CipherAES128GCMSHA256;
  Result[1] := TLS13CipherAES256GCMSHA384;
  Result[2] := TLS13CipherChaCha20Poly1305SHA256;
end;

function TLS13DefaultSupportedGroups: TTLSNamedGroups;
begin
  SetLength(Result, 2);
  Result[0] := TLS13GroupSecp256r1;
  Result[1] := TLS13GroupSecp384r1;
end;

function TLS13DefaultSignatureSchemes: TTLSSignatureSchemes;
begin
  SetLength(Result, 3);
  Result[0] := TLSSigECDSA_Secp256r1_SHA256;
  Result[1] := TLSSigECDSA_Secp384r1_SHA384;
  Result[2] := TLSSigRSA_PSS_RSAE_SHA256;
end;

function TLS13SignatureSchemeSupported(AScheme: TTLSSignatureScheme): Boolean;
begin
  case AScheme of
    TLSSigECDSA_Secp256r1_SHA256,
    TLSSigECDSA_Secp384r1_SHA384,
    TLSSigRSA_PSS_RSAE_SHA256: Result := True;
  else
    Result := False;
  end;
end;

function DefaultTLS13ClientHelloOptions: TTLS13ClientHelloOptions;
begin
  Result.ServerName := '';
  Result.ClientRandom := nil;
  Result.LegacySessionID := nil;
  Result.CipherSuites := nil;
  Result.SupportedGroups := nil;
  Result.SignatureSchemes := nil;
  Result.KeyShareOffers := nil;
  { Compatibility mode is on by default: a non-empty legacy_session_id
    keeps middleboxes that assume a TLS 1.2 session id happy (RFC 8446,
    Appendix D.4). }
  Result.CompatibilityMode := True;
  Result.PskKeyExchangeModes := False;
end;

function TLS13GenerateKeyShareOffers(
  const AGroups: TTLSNamedGroups): TTLS13KeyShareOffers;
var
  i: Integer;
begin
  { Validate every group before any key material is created, so that a
    rejected group never leaves stray private keys behind. }
  for i := 0 to High(AGroups) do
    if not TLS13GroupSupported(AGroups[i]) then
      raise ETLS13Error.CreateFmt(
        'ClientHello: unsupported group %d (key shares can only be '
        + 'generated for secp256r1 and secp384r1)', [AGroups[i]]);
  SetLength(Result, Length(AGroups));
  for i := 0 to High(AGroups) do
  begin
    Result[i].KeyShare := TLS13KeyShareGenerate(AGroups[i]);
    Result[i].Entry.Group := AGroups[i];
    Result[i].Entry.KeyExchange := Result[i].KeyShare.PublicKey;
  end;
end;

procedure TLS13KeyShareOffersFree(var AOffers: TTLS13KeyShareOffers);
var
  i: Integer;
begin
  for i := 0 to High(AOffers) do
    TLS13KeyShareFree(AOffers[i].KeyShare);
  AOffers := nil;
end;

function TLS13KeyShareEntries(
  const AOffers: TTLS13KeyShareOffers): TTLS13KeyShareEntries;
var
  i: Integer;
begin
  SetLength(Result, Length(AOffers));
  for i := 0 to High(AOffers) do
    Result[i] := AOffers[i].Entry;
end;

function EncodeTLS13KeyShareExtension(
  const AEntries: TTLS13KeyShareEntries): TTLSExtension;
var
  Body: TBytes;
  i: Integer;
begin
  Body := nil;
  for i := 0 to High(AEntries) do
    Body := TLS13BufBytes(Body,
      TLS13EncodeKeyShareEntry(AEntries[i].Group, AEntries[i].KeyExchange));
  if Length(Body) > High(Word) then
    raise ETLS13Error.Create('key_share: client_shares longer than 65535 bytes');
  Result.ExtType := TLS13ExtKeyShare;
  Result.Data := TLS13BufWord(nil, Length(Body));
  Result.Data := TLS13BufBytes(Result.Data, Body);
end;

function EncodeTLS13SupportedVersionsExtension: TTLSExtension;
begin
  Result.ExtType := TLS13ExtSupportedVersions;
  { opaque versions<2..254>: one byte list length, then uint16 values. }
  Result.Data := TLS13BufByte(nil, 2);
  Result.Data := TLS13BufWord(Result.Data, TLS13Version);
end;

function EncodeTLS13PskKeyExchangeModesExtension: TTLSExtension;
begin
  Result.ExtType := TLS13ExtPskKeyExchangeModes;
  { opaque ke_modes<1..255>: one byte list length, then byte values. }
  Result.Data := TLS13BufByte(nil, 1);
  Result.Data := TLS13BufByte(Result.Data, TLS13PskDheKe);
end;

function BuildTLS13ClientHelloExtensions(
  const AOptions: TTLS13ClientHelloOptions): TTLSExtensions;
var
  n: Integer;
  Groups: TTLSNamedGroups;
  Schemes: TTLSSignatureSchemes;
begin
  Result := nil;
  n := 0;
  { server_name (RFC 6066; required for virtual hosting). }
  if AOptions.ServerName <> '' then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLSServerNameExtension(AOptions.ServerName);
    Inc(n);
  end;
  { supported_groups (RFC 8446, 4.2.7). }
  Groups := AOptions.SupportedGroups;
  if Length(Groups) = 0 then
    Groups := TLS13DefaultSupportedGroups;
  SetLength(Result, n + 1);
  Result[n] := EncodeTLSSupportedGroupsExtension(Groups);
  Inc(n);
  { signature_algorithms (RFC 8446, 4.2.3): mandatory in TLS 1.3. }
  Schemes := AOptions.SignatureSchemes;
  if Length(Schemes) = 0 then
    Schemes := TLS13DefaultSignatureSchemes;
  SetLength(Result, n + 1);
  Result[n] := EncodeTLSSignatureAlgorithmsExtension(Schemes);
  Inc(n);
  { supported_versions (RFC 8446, 4.2.1): mandatory in TLS 1.3. }
  SetLength(Result, n + 1);
  Result[n] := EncodeTLS13SupportedVersionsExtension;
  Inc(n);
  { key_share (RFC 8446, 4.2.8). }
  SetLength(Result, n + 1);
  Result[n] := EncodeTLS13KeyShareExtension(
    TLS13KeyShareEntries(AOptions.KeyShareOffers));
  Inc(n);
  { psk_key_exchange_modes (RFC 8446, 4.2.9): only when asked for; this
    client does not resume sessions, so it stays off by default. }
  if AOptions.PskKeyExchangeModes then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLS13PskKeyExchangeModesExtension;
    Inc(n);
  end;
end;

function BuildTLS13ClientHelloBody(
  const AOptions: TTLS13ClientHelloOptions): TBytes;
var
  Rand, SessionID, SuiteBytes, ExtBytes: TBytes;
  Suites: TTLSCipherSuites;
  Schemes: TTLSSignatureSchemes;
  Groups: TTLSNamedGroups;
  i: Integer;
begin
  { random: 32 bytes (RFC 8446, 4.1.2). }
  Rand := AOptions.ClientRandom;
  if Length(Rand) = 0 then
    RandomBytes(Rand, TLS13ClientRandomLen)
  else if Length(Rand) <> TLS13ClientRandomLen then
    raise ETLS13Error.CreateFmt('ClientHello: random is %d bytes (need %d)',
      [Length(Rand), TLS13ClientRandomLen]);

  { legacy_session_id: empty when compatibility mode is off (RFC 8446,
    4.1.2), otherwise the 32 random bytes of Appendix D.4. }
  SessionID := AOptions.LegacySessionID;
  if Length(SessionID) = 0 then
  begin
    if AOptions.CompatibilityMode then
      RandomBytes(SessionID, TLS13CompatSessionIDLen);
  end
  else if Length(SessionID) > TLS13CompatSessionIDLen then
    raise ETLS13Error.CreateFmt(
      'ClientHello: legacy_session_id is %d bytes (maximum %d)',
      [Length(SessionID), TLS13CompatSessionIDLen])
  else if AOptions.CompatibilityMode and
    (Length(SessionID) <> TLS13CompatSessionIDLen) then
    raise ETLS13Error.CreateFmt(
      'ClientHello: compatibility mode needs a %d-byte legacy_session_id, '
      + 'got %d', [TLS13CompatSessionIDLen, Length(SessionID)]);

  { cipher_suites: AEAD only (RFC 8446, B.4). }
  Suites := AOptions.CipherSuites;
  if Length(Suites) = 0 then
    Suites := TLS13DefaultCipherSuites;
  SuiteBytes := nil;
  for i := 0 to High(Suites) do
  begin
    if not TLS13CipherSuiteSupported(Suites[i]) then
      raise ETLS13Error.CreateFmt(
        'ClientHello: unsupported cipher suite 0x%.4x', [Suites[i]]);
    SuiteBytes := TLS13BufWord(SuiteBytes, Suites[i]);
  end;

  { supported_groups: only curves this client can actually use. }
  Groups := AOptions.SupportedGroups;
  if Length(Groups) = 0 then
    Groups := TLS13DefaultSupportedGroups;
  for i := 0 to High(Groups) do
    if not TLS13GroupSupported(Groups[i]) then
      raise ETLS13Error.CreateFmt(
        'ClientHello: unsupported group %d in supported_groups', [Groups[i]]);

  { signature_algorithms (RFC 8446, 4.2.3): advertise only schemes this
    client can verify. An unsupported one is rejected up front rather than
    offered, so the server cannot select a scheme we would have to refuse
    in CertificateVerify. }
  Schemes := AOptions.SignatureSchemes;
  if Length(Schemes) = 0 then
    Schemes := TLS13DefaultSignatureSchemes;
  for i := 0 to High(Schemes) do
    if not TLS13SignatureSchemeSupported(Schemes[i]) then
      raise ETLS13Error.CreateFmt(
        'ClientHello: unsupported signature scheme 0x%.4x', [Schemes[i]]);

  { key_share: at least one offer is required, and each offered group must
    be listed in supported_groups (RFC 8446, 4.2.8). }
  if Length(AOptions.KeyShareOffers) = 0 then
    raise ETLS13Error.Create('ClientHello: no key_share offer (generate one '
      + 'with TLS13GenerateKeyShareOffers)');
  for i := 0 to High(AOptions.KeyShareOffers) do
    if not TLS13GroupInList(Groups, AOptions.KeyShareOffers[i].Entry.Group) then
      raise ETLS13Error.CreateFmt(
        'ClientHello: key_share for group %d is not in supported_groups',
        [AOptions.KeyShareOffers[i].Entry.Group]);

  { Body: legacy_version || random || legacy_session_id || cipher_suites ||
    legacy_compression_methods || extensions (RFC 8446, 4.1.2). }
  Result := TLS13BufWord(nil, TLS13LegacyVersion);
  Result := TLS13BufBytes(Result, Rand);
  Result := TLS13BufByte(Result, Length(SessionID));
  Result := TLS13BufBytes(Result, SessionID);
  Result := TLS13BufWord(Result, Length(SuiteBytes));
  Result := TLS13BufBytes(Result, SuiteBytes);
  { legacy_compression_methods: a single null byte, as RFC 8446 (4.1.2)
    demands (it is not a negotiation, just a compatibility field). }
  Result := TLS13BufByte(Result, 1);
  Result := TLS13BufByte(Result, 0);
  ExtBytes := EncodeTLSExtensions(BuildTLS13ClientHelloExtensions(AOptions));
  Result := TLS13BufBytes(Result, ExtBytes);
end;

function BuildTLS13ClientHello(
  const AOptions: TTLS13ClientHelloOptions): TBytes;
begin
  Result := EncodeTLSHandshakeMessage(htClientHello,
    BuildTLS13ClientHelloBody(AOptions));
end;

function BuildTLS13ClientHelloOptions(const AServerName: string;
  const AClientRandom: TBytes): TTLS13ClientHelloOptions;
begin
  Result := DefaultTLS13ClientHelloOptions;
  Result.ServerName := AServerName;
  Result.ClientRandom := AClientRandom;
  Result.CipherSuites := TLS13DefaultCipherSuites;
  Result.SupportedGroups := TLS13DefaultSupportedGroups;
  Result.SignatureSchemes := TLS13DefaultSignatureSchemes;
  Result.KeyShareOffers := TLS13GenerateKeyShareOffers(Result.SupportedGroups);
end;

procedure WriteTLS13ClientHello(ATransport: ITLSTransport;
  const AOptions: TTLS13ClientHelloOptions; AVersion: Word);
begin
  WriteTLSHandshakeMessage(ATransport, htClientHello,
    BuildTLS13ClientHelloBody(AOptions), AVersion);
end;

{--- ServerHello (RFC 8446, 4.1.3) --------------------------------------- }

{ Read 2 bytes big-endian; the caller validates the bounds first. }
function TLS13ReadWordAt(const AData: TBytes; AOffset: Integer): Word;
begin
  Result := (Word(AData[AOffset]) shl 8) or Word(AData[AOffset + 1]);
end;

{ Read 3 bytes big-endian; the caller validates the bounds first. }
function TLS13ReadTripleAt(const AData: TBytes; AOffset: Integer): LongWord;
begin
  Result := (LongWord(AData[AOffset]) shl 16) or
            (LongWord(AData[AOffset + 1]) shl 8) or
            LongWord(AData[AOffset + 2]);
end;

{ Byte-wise comparison of two public values (random, session-id echo).
  No secret material is involved, so constant time is not required. }
function TLS13BytesEqual(const A, B: TBytes): Boolean;
var
  i: Integer;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  for i := 0 to High(A) do
    if A[i] <> B[i] then
      Exit(False);
  Result := True;
end;

function TLS13IsHelloRetryRequest(const ARandom: TBytes): Boolean;
var
  i: Integer;
begin
  if Length(ARandom) <> Length(TLS13HelloRetryRequestRandom) then
    Exit(False);
  for i := 0 to High(TLS13HelloRetryRequestRandom) do
    if ARandom[i] <> TLS13HelloRetryRequestRandom[i] then
      Exit(False);
  Result := True;
end;

{ RFC 8446, 4.2 forbids a peer from sending the same extension twice.
  AContext names the message being parsed and is used in the error text. }
procedure TLS13CheckNoDuplicateExtensions(const AExtensions: TTLSExtensions;
  const AContext: string);
var
  i, j: Integer;
begin
  for i := 0 to High(AExtensions) do
    for j := 0 to i - 1 do
      if AExtensions[i].ExtType = AExtensions[j].ExtType then
        raise ETLS13Error.CreateFmt(
          'TLS 1.3 %s: duplicate extension type %d',
          [AContext, AExtensions[i].ExtType]);
end;

function ParseTLS13ServerHelloInternal(const AData: TBytes;
  const ALegacySessionID: TBytes; ACheckSessionID: Boolean): TTLS13ServerHello;
var
  Pos, ExtStart, ExtLen, SessLen: Integer;
  Ext: TTLSExtension;
begin
  Result.LegacyVersion := 0;
  Result.Random := nil;
  Result.LegacySessionIDEcho := nil;
  Result.CipherSuite := 0;
  Result.LegacyCompressionMethod := 0;
  Result.Extensions := nil;
  Result.SupportedVersion := 0;
  Result.HasKeyShare := False;
  Result.KeyShare.Group := 0;
  Result.KeyShare.KeyExchange := nil;

  Pos := 0;

  { ProtocolVersion legacy_version = 0x0303 (RFC 8446, 4.1.3). }
  if Length(AData) < Pos + 2 then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated legacy_version');
  Result.LegacyVersion := TLS13ReadWordAt(AData, Pos);
  Inc(Pos, 2);
  if Result.LegacyVersion <> TLS13LegacyVersion then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: legacy_version 0x%.4x, expected 0x0303',
      [Result.LegacyVersion]);

  { Random random (32 bytes). }
  if Length(AData) < Pos + TLS13ClientRandomLen then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated random');
  Result.Random := Copy(AData, Pos, TLS13ClientRandomLen);
  Inc(Pos, TLS13ClientRandomLen);

  { A HelloRetryRequest is a ServerHello-shaped message distinguished only
    by its random (RFC 8446, 4.1.3). It is recognized before any other
    field is interpreted, so it can never be mistaken for an accepted
    ServerHello: this client has no second ClientHello and fails loudly. }
  if TLS13IsHelloRetryRequest(Result.Random) then
    raise ETLS13Error.Create(
      'TLS 1.3: server sent a HelloRetryRequest, which is not supported');

  { opaque legacy_session_id_echo<0..32>: must match what we sent. }
  if Length(AData) < Pos + 1 then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: truncated legacy_session_id_echo');
  SessLen := AData[Pos];
  Inc(Pos);
  if SessLen > TLS13CompatSessionIDLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: legacy_session_id_echo %d bytes (maximum %d)',
      [SessLen, TLS13CompatSessionIDLen]);
  if Length(AData) < Pos + SessLen then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: truncated legacy_session_id_echo');
  Result.LegacySessionIDEcho := Copy(AData, Pos, SessLen);
  Inc(Pos, SessLen);
  if ACheckSessionID and not TLS13BytesEqual(Result.LegacySessionIDEcho,
    ALegacySessionID) then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: legacy_session_id_echo does not match the '
      + 'legacy_session_id sent in the ClientHello');

  { CipherSuite cipher_suite: AEAD only (RFC 8446, B.4). }
  if Length(AData) < Pos + 2 then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated cipher_suite');
  Result.CipherSuite := TLS13ReadWordAt(AData, Pos);
  Inc(Pos, 2);
  if not TLS13CipherSuiteSupported(Result.CipherSuite) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: cipher suite 0x%.4x is not a supported TLS 1.3 '
      + 'AEAD suite', [Result.CipherSuite]);

  { uint8 legacy_compression_method = 0 (RFC 8446, 4.1.3). }
  if Length(AData) < Pos + 1 then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: truncated legacy_compression_method');
  Result.LegacyCompressionMethod := AData[Pos];
  Inc(Pos);
  if Result.LegacyCompressionMethod <> 0 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: legacy_compression_method %d, expected 0',
      [Result.LegacyCompressionMethod]);

  { Extension extensions<6..2^16-1>: mandatory in a ServerHello. }
  ExtStart := Pos;
  if Length(AData) < ExtStart + 2 then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: missing extensions');
  ExtLen := Integer(TLS13ReadWordAt(AData, ExtStart));
  if Length(AData) <> ExtStart + 2 + ExtLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: extension block declares %d bytes, %d available',
      [ExtLen, Length(AData) - ExtStart - 2]);
  Result.Extensions := DecodeTLSExtensions(Copy(AData, ExtStart, 2 + ExtLen));
  TLS13CheckNoDuplicateExtensions(Result.Extensions, 'ServerHello');

  { supported_versions (RFC 8446, 4.2.1): mandatory; the selected version
    must be TLS 1.3, otherwise the server refused to negotiate it. }
  if not FindTLSExtension(Result.Extensions, TLS13ExtSupportedVersions, Ext)
  then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: missing supported_versions extension');
  if Length(Ext.Data) <> 2 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: supported_versions is %d bytes, expected 2',
      [Length(Ext.Data)]);
  Result.SupportedVersion := TLS13ReadWordAt(Ext.Data, 0);
  if Result.SupportedVersion <> TLS13Version then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: server selected version 0x%.4x instead of TLS 1.3 (0x0304)',
      [Result.SupportedVersion]);

  { key_share (RFC 8446, 4.2.8): mandatory for (EC)DHE. This client never
    offers PSK, so an absent key_share cannot be legitimate. }
  if not FindTLSExtension(Result.Extensions, TLS13ExtKeyShare, Ext) then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: missing key_share extension');
  try
    Result.KeyShare := TLS13ParseKeyShareEntry(Ext.Data);
  except
    on E: ETLS13Error do
      raise;
    on E: Exception do
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 ServerHello: malformed key_share extension: %s',
        [E.Message]);
  end;
  Result.HasKeyShare := True;
  if not TLS13GroupSupported(Result.KeyShare.Group) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ServerHello: server selected unsupported group %d '
      + '(only secp256r1 and secp384r1 are supported)',
      [Result.KeyShare.Group]);

  { Extensions specific to PSK / 0-RTT handshakes: this client offers
    neither, so receiving them is a protocol error (RFC 8446, 4.2). }
  if FindTLSExtension(Result.Extensions, TLS13ExtPreSharedKey, Ext) then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: unexpected pre_shared_key extension');
  if FindTLSExtension(Result.Extensions, TLS13ExtEarlyData, Ext) then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: unexpected early_data extension');
end;

function ParseTLS13ServerHello(const AData: TBytes): TTLS13ServerHello;
begin
  Result := ParseTLS13ServerHelloInternal(AData, nil, False);
end;

function ParseTLS13ServerHello(const AData: TBytes;
  const ALegacySessionID: TBytes): TTLS13ServerHello;
begin
  Result := ParseTLS13ServerHelloInternal(AData, ALegacySessionID, True);
end;

function ParseTLS13ServerHelloMessage(
  const AMsg: TTLSHandshakeMessage): TTLS13ServerHello;
begin
  if AMsg.MsgType <> htServerHello then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: expected a ServerHello, got handshake message %d',
      [Ord(AMsg.MsgType)]);
  Result := ParseTLS13ServerHello(AMsg.Body);
end;

{--- EncryptedExtensions (RFC 8446, 4.3.1) ------------------------------- }

{ Extension types that are not valid in EncryptedExtensions: RFC 8446
  defines them for ClientHello, ServerHello, HelloRetryRequest or
  CertificateRequest only, or they acknowledge a capability this client
  never offers (PSK resumption, 0-RTT data, an HRR cookie). Receiving one
  is a handshake error (RFC 8446, 4.2: an extension may only be sent where
  the specification allows it), so it is rejected instead of being
  returned as opaque data. }
procedure TLS13CheckEncryptedExtensionsAllowed(
  const AExtensions: TTLSExtensions);
const
  Msg = 'TLS 1.3 EncryptedExtensions: unexpected ';
var
  i: Integer;
begin
  for i := 0 to High(AExtensions) do
    case AExtensions[i].ExtType of
      TLS13ExtSupportedVersions:
        raise ETLS13Error.Create(
          Msg + 'supported_versions extension (that extension is only valid '
          + 'in ClientHello and ServerHello)');
      TLS13ExtKeyShare:
        raise ETLS13Error.Create(
          Msg + 'key_share extension (that extension is only valid in '
          + 'ClientHello, ServerHello and HelloRetryRequest)');
      TLS13ExtSignatureAlgorithms:
        raise ETLS13Error.Create(
          Msg + 'signature_algorithms extension (that extension is only '
          + 'valid in ClientHello and CertificateRequest)');
      TLS13ExtSignatureAlgorithmsCert:
        raise ETLS13Error.Create(
          Msg + 'signature_algorithms_cert extension (that extension is '
          + 'only valid in ClientHello and CertificateRequest)');
      TLS13ExtPreSharedKey:
        raise ETLS13Error.Create(
          Msg + 'pre_shared_key extension (that extension is only valid in '
          + 'ClientHello and ServerHello)');
      TLS13ExtPskKeyExchangeModes:
        raise ETLS13Error.Create(
          Msg + 'psk_key_exchange_modes extension (that extension is only '
          + 'valid in ClientHello)');
      TLS13ExtEarlyData:
        raise ETLS13Error.Create(
          Msg + 'early_data extension (this client does not offer 0-RTT '
          + 'data)');
      TLS13ExtCookie:
        raise ETLS13Error.Create(
          Msg + 'cookie extension (that extension is only valid in '
          + 'ClientHello and HelloRetryRequest)');
      TLS13ExtPostHandshakeAuth:
        raise ETLS13Error.Create(
          Msg + 'post_handshake_auth extension (that extension is only '
          + 'valid in ClientHello)');
    end;
end;

function ParseTLS13EncryptedExtensions(
  const AData: TBytes): TTLS13EncryptedExtensions;
var
  ExtLen: Integer;
begin
  Result.Extensions := nil;

  { Extension extensions<0..2^16-1>: the two-byte length prefix is always
    present, an empty list is legal (RFC 8446, 4.3.1). }
  if Length(AData) < 2 then
    raise ETLS13Error.Create(
      'TLS 1.3 EncryptedExtensions: missing extensions block');
  ExtLen := Integer(TLS13ReadWordAt(AData, 0));
  if Length(AData) <> 2 + ExtLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 EncryptedExtensions: extension block declares %d bytes, '
      + '%d available', [ExtLen, Length(AData) - 2]);
  try
    Result.Extensions := DecodeTLSExtensions(Copy(AData, 0, 2 + ExtLen));
  except
    on E: ETLS13Error do
      raise;
    on E: Exception do
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 EncryptedExtensions: malformed extension block: %s',
        [E.Message]);
  end;

  TLS13CheckNoDuplicateExtensions(Result.Extensions, 'EncryptedExtensions');
  TLS13CheckEncryptedExtensionsAllowed(Result.Extensions);
end;

function ParseTLS13EncryptedExtensionsMessage(
  const AMsg: TTLSHandshakeMessage): TTLS13EncryptedExtensions;
begin
  if AMsg.MsgType <> htEncryptedExtensions then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: expected an EncryptedExtensions, got handshake message %d',
      [Ord(AMsg.MsgType)]);
  Result := ParseTLS13EncryptedExtensions(AMsg.Body);
end;

{--- Certificate (RFC 8446, 4.4.2) --------------------------------------- }

{ Decodes one `Extension extensions<0..2^16-1>` block that starts at
  AOffset and is exactly ALen bytes long. AContext names the entry and is
  used in error messages. }
function TLS13DecodeCertificateExtensions(const AData: TBytes;
  AOffset, ALen: Integer; const AContext: string): TTLSExtensions;
var
  ExtLen: Integer;
begin
  Result := nil;
  if ALen < 2 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 Certificate: %s: missing extensions block', [AContext]);
  ExtLen := Integer(TLS13ReadWordAt(AData, AOffset));
  if ALen <> 2 + ExtLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 Certificate: %s: extension block declares %d bytes, '
      + '%d available', [AContext, ExtLen, ALen - 2]);
  try
    Result := DecodeTLSExtensions(Copy(AData, AOffset, ALen));
  except
    on E: ETLS13Error do
      raise;
    on E: Exception do
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: %s: malformed extension block: %s',
        [AContext, E.Message]);
  end;
  TLS13CheckNoDuplicateExtensions(Result, 'Certificate ' + AContext);
end;

function ParseTLS13Certificate(const AData: TBytes): TTLS13Certificate;
var
  Pos, CtxLen, ListLen, CertLen, ExtLen, n: Integer;
  EntryContext: string;
begin
  Result.RequestContext := nil;
  Result.Entries := nil;

  { opaque certificate_request_context<0..2^8-1>; the client never sends a
    Certificate, so the 1-RTT server flight always carries an empty one. }
  if Length(AData) < 1 then
    raise ETLS13Error.Create(
      'TLS 1.3 Certificate: missing certificate_request_context');
  CtxLen := AData[0];
  Pos := 1;
  if Pos + CtxLen > Length(AData) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 Certificate: certificate_request_context declares %d bytes, '
      + '%d available', [CtxLen, Length(AData) - Pos]);
  Result.RequestContext := Copy(AData, Pos, CtxLen);
  Inc(Pos, CtxLen);
  if CtxLen <> 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 Certificate: non-empty certificate_request_context (this '
      + 'client only parses the server Certificate of a 1-RTT handshake)');

  { CertificateEntry certificate_list<0..2^24-1>. }
  if Pos + 3 > Length(AData) then
    raise ETLS13Error.Create(
      'TLS 1.3 Certificate: missing certificate_list length');
  ListLen := Integer(TLS13ReadTripleAt(AData, Pos));
  Inc(Pos, 3);
  if ListLen <> Length(AData) - Pos then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 Certificate: certificate_list declares %d bytes, %d '
      + 'available', [ListLen, Length(AData) - Pos]);
  if ListLen = 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 Certificate: empty certificate_list (a 1-RTT server MUST NOT '
      + 'send one, RFC 8446, 4.4.2)');

  { Entries, from the leaf (index 0) to the root. }
  n := 0;
  while Pos < Length(AData) do
  begin
    if Pos + 3 > Length(AData) then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: entry %d: truncated certificate length', [n]);
    CertLen := Integer(TLS13ReadTripleAt(AData, Pos));
    Inc(Pos, 3);
    if CertLen = 0 then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: entry %d has an empty cert_data', [n]);
    if Pos + CertLen > Length(AData) then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: entry %d declares %d certificate bytes, '
        + '%d available', [n, CertLen, Length(AData) - Pos]);
    SetLength(Result.Entries, n + 1);
    Result.Entries[n].Certificate := Copy(AData, Pos, CertLen);
    Inc(Pos, CertLen);

    { Extension extensions<0..2^16-1> of this entry. }
    if Pos + 2 > Length(AData) then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: entry %d: missing extensions block', [n]);
    ExtLen := Integer(TLS13ReadWordAt(AData, Pos));
    if Pos + 2 + ExtLen > Length(AData) then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: entry %d: extension block declares %d bytes, '
        + '%d available', [n, ExtLen, Length(AData) - Pos - 2]);
    EntryContext := Format('entry %d', [n]);
    Result.Entries[n].Extensions :=
      TLS13DecodeCertificateExtensions(AData, Pos, 2 + ExtLen, EntryContext);
    Inc(Pos, 2 + ExtLen);
    Inc(n);
  end;
end;

function ParseTLS13CertificateMessage(
  const AMsg: TTLSHandshakeMessage): TTLS13Certificate;
begin
  if AMsg.MsgType <> htCertificate then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: expected a Certificate, got handshake message %d',
      [Ord(AMsg.MsgType)]);
  Result := ParseTLS13Certificate(AMsg.Body);
end;

function TLS13CertificateChain(
  const ACertificate: TTLS13Certificate): TTLS12CertChain;
var
  msg: TTLSCertificateMessage;
  i: LongInt;
begin
  { TLS 1.3 cert_data is the same DER as the TLS 1.2 ASN.1Cert, and both
    lists run from the leaf to the root, so the message can be handed to the
    TLS 1.2 chain parser without any reinterpretation of the bytes. }
  SetLength(msg.Certificates, Length(ACertificate.Entries));
  for i := 0 to Length(ACertificate.Entries) - 1 do
    msg.Certificates[i].Data := ACertificate.Entries[i].Certificate;
  try
    Result := ParseTLS12CertChain(msg);
  except
    on E: ETLS13Error do
      raise;
    on E: Exception do
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 Certificate: cannot parse the server chain: %s',
        [E.Message]);
  end;
end;

function VerifyTLS13Certificate(const ACertificate: TTLS13Certificate;
  const ATrustStore: TCertStore; AHops: LongInt; ANow: TDateTime): TVerifyResult;
var
  chain: TTLS12CertChain;
begin
  chain := TLS13CertificateChain(ACertificate);
  try
    Result := chain.Verify(ATrustStore, AHops, ANow);
  finally
    chain.Free;
  end;
end;

function VerifyTLS13CertificateMessage(const AMsg: TTLSHandshakeMessage;
  const ATrustStore: TCertStore; AHops: LongInt; ANow: TDateTime): TVerifyResult;
begin
  Result := VerifyTLS13Certificate(
    ParseTLS13CertificateMessage(AMsg), ATrustStore, AHops, ANow);
end;

procedure CheckTLS13Certificate(const ACertificate: TTLS13Certificate;
  const ATrustStore: TCertStore; AHops: LongInt; ANow: TDateTime);
var
  vr: TVerifyResult;
begin
  vr := VerifyTLS13Certificate(ACertificate, ATrustStore, AHops, ANow);
  if not vr.OK then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: certificate chain verification failed: %s', [vr.Reason]);
end;

{--- CertificateVerify (RFC 8446, 4.4.3) --------------------------------- }

{ Number of 0x20 bytes that pad the context string (RFC 8446, 4.4.3) and
  the value of each of them. }
const
  TLS13CertVerifyPadding = 64;
  TLS13CertVerifyPaddingByte = $20;

function TLS13CertificateVerifyContent(const AContextString: AnsiString;
  const ATranscriptHash: TBytes): TBytes;
var
  N, Offset: Integer;
begin
  N := Length(AContextString);
  if N = 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 CertificateVerify: empty context string');
  { 0x20 * 64 || context string || 0x00 || Transcript-Hash }
  SetLength(Result, TLS13CertVerifyPadding + N + 1 +
    Length(ATranscriptHash));
  FillChar(Result[0], TLS13CertVerifyPadding, TLS13CertVerifyPaddingByte);
  Move(AContextString[1], Result[TLS13CertVerifyPadding], N);
  Offset := TLS13CertVerifyPadding + N;
  Result[Offset] := 0;
  if Length(ATranscriptHash) > 0 then
    Move(ATranscriptHash[0], Result[Offset + 1], Length(ATranscriptHash));
end;

function TLS13CertificateVerifyContentFromTranscript(
  const AContextString: AnsiString; AHash: THashKind;
  const ATranscript: TBytes): TBytes;
begin
  Result := TLS13CertificateVerifyContent(AContextString,
    TLS13TranscriptHash(AHash, ATranscript));
end;

function TLS13ServerCertificateVerifyContent(AHash: THashKind;
  const ATranscriptHash: TBytes): TBytes;
begin
  Result := TLS13CertificateVerifyContent(
    TLS13ContextStringServerCertificateVerify, ATranscriptHash);
end;

function TLS13ClientCertificateVerifyContent(AHash: THashKind;
  const ATranscriptHash: TBytes): TBytes;
begin
  Result := TLS13CertificateVerifyContent(
    TLS13ContextStringClientCertificateVerify, ATranscriptHash);
end;

{--- CertificateVerify signature verification (RFC 8446, 4.4.3) --------- }

{ OIDs of the two NIST curves this unit can verify ECDSA on, as they
  appear in SubjectPublicKeyInfo (RFC 5480). }
const
  TLS13ECCurveOIDP256 = '1.2.840.10045.3.1.7';  { prime256v1 / secp256r1 }
  TLS13ECCurveOIDP384 = '1.3.132.0.34';         { secp384r1 }

{ TLS 1.3 context strings and x509 OIDs are different things: the scheme
  fixes the curve, so the same mapping also names the hash the signature
  must use (RFC 8446, 4.2.3). }
function TLS13ECDSASignatureSchemeCurveOID(
  AScheme: TTLSSignatureScheme): string;
begin
  case AScheme of
    TLSSigECDSA_Secp256r1_SHA256: Result := TLS13ECCurveOIDP256;
    TLSSigECDSA_Secp384r1_SHA384: Result := TLS13ECCurveOIDP384;
  else
    Result := '';
  end;
end;

function TLS13ECDSASignatureSchemeCurve(
  AScheme: TTLSSignatureScheme): TECCurve;
begin
  case AScheme of
    TLSSigECDSA_Secp256r1_SHA256: Result := CurveP256;
    TLSSigECDSA_Secp384r1_SHA384: Result := CurveP384;
  else
    Result := nil;
  end;
end;

function VerifyTLS13ECDSASignature(const ACert: TX509Cert;
  AScheme: TTLSSignatureScheme; const AContent, ASignature: TBytes): Boolean;
var
  Curve: TECCurve;
begin
  Result := False;
  if ACert = nil then Exit;
  if Length(AContent) = 0 then Exit;
  if Length(ASignature) = 0 then Exit;
  if not TLS13SignatureSchemeSupported(AScheme) then Exit;

  { Only the two ECDSA schemes take this path; an RSA-PSS or Ed25519
    scheme yields nil here and is rejected rather than mis-verified. }
  Curve := TLS13ECDSASignatureSchemeCurve(AScheme);
  if Curve = nil then Exit;
  try
    if ACert.SPKI.KeyType <> pkEC then Exit;
    if ACert.SPKI.Point = nil then Exit;
    { The public key must be on exactly the curve named by the scheme:
      the scheme also fixes the hash (SHA-256 for P-256, SHA-384 for
      P-384), so key and scheme together determine what is verified
      (RFC 8446, 4.2.3 and 4.4.3). }
    if ACert.SPKI.CurveOID <> TLS13ECDSASignatureSchemeCurveOID(AScheme) then
      Exit;
    { VerifyDataSignature (tls.certstore) decodes the DER ECDSA-Sig-Value
      and calls ECDSAVerify (tls.ec), which hashes AContent with the hash
      of the key's curve — exactly the hash the scheme requires. A
      malformed DER signature is reported as a verification failure. }
    Result := VerifyDataSignature(ACert, AContent, ASignature,
      TLS12SignatureSchemeX509OID(AScheme));
  finally
    Curve.Free;
  end;
end;

function VerifyTLS13RSAPSSSignature(const ACert: TX509Cert;
  AScheme: TTLSSignatureScheme; const AContent, ASignature: TBytes): Boolean;
var
  Key: TRSAKey;
  Sig: TBN;
  Digest: TBytes;
begin
  Result := False;
  if ACert = nil then Exit;
  if Length(AContent) = 0 then Exit;
  if Length(ASignature) = 0 then Exit;

  { CertificateVerify in TLS 1.3 accepts only rsa_pss_rsae_sha256 among the
    RSA schemes (RFC 8446, 4.2.3): the legacy rsa_pkcs1_* schemes must never
    be verified under the PSS rules. }
  if AScheme <> TLSSigRSA_PSS_RSAE_SHA256 then Exit;
  if not TLS13SignatureSchemeSupported(AScheme) then Exit;

  { The certificate key must be an RSA public key; an EC or unknown key is
    never verified as RSA. }
  if ACert.SPKI.KeyType <> pkRSA then Exit;
  if (ACert.SPKI.RSAModulus = nil) or (ACert.SPKI.RSAExponent = nil) then Exit;

  { RSASSA-PSS-VERIFY (RFC 8017, 9.1.2) with SHA-256 and a salt as long as
    the hash. TRSAKey.VerifyPSS recovers EM = Signature^e mod n and runs
    EMSA-PSS verification (padding and salt checks are constant time). The
    hash is fixed by the scheme, so the digest is SHA-256(AContent). }
  Digest := SHA256(AContent);
  Sig := TBN.FromBytes(ASignature, True);
  try
    Key := TRSAKey.FromPublic(ACert.SPKI.RSAModulus, ACert.SPKI.RSAExponent);
    try
      Result := Key.VerifyPSS(Sig, Digest, TLS13HashLen(hkSHA256));
    finally
      Key.Free;
    end;
  finally
    Sig.Free;
  end;
end;

{--- key schedule (RFC 8446, 7.1) ---------------------------------------- }

{ Zeros of HashLen bytes — the "0" input of the extract stages and the
  salt of the early secret. }
function TLS13Zeros(AHash: THashKind): TBytes;
var
  N: Integer;
begin
  N := TLS13HashLen(AHash);
  SetLength(Result, N);
  if N > 0 then
    FillChar(Result[0], N, 0);
end;

function TLS13CipherSuiteHashKind(ASuite: TTLSCipherSuite): THashKind;
begin
  case ASuite of
    TLS13CipherAES128GCMSHA256,
    TLS13CipherChaCha20Poly1305SHA256:
      Result := hkSHA256;
    TLS13CipherAES256GCMSHA384:
      Result := hkSHA384;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 key schedule: unsupported cipher suite 0x%.4X', [ASuite]);
  end;
end;

function TLS13TranscriptHash(AHash: THashKind;
  const ATranscript: TBytes): TBytes;
begin
  case AHash of
    hkSHA256: Result := SHA256(ATranscript);
    hkSHA384: Result := SHA384(ATranscript);
    hkSHA512: Result := SHA512(ATranscript);
  else
    raise ETLS13Error.Create(
      'TLS 1.3 key schedule: unsupported transcript hash');
  end;
end;

function TLS13DeriveSecretFromHash(AHash: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const ATranscriptHash: TBytes): TBytes;
begin
  Result := HKDFExpandLabel(AHash, ASecret, ALabel, ATranscriptHash,
    TLS13HashLen(AHash));
end;

function TLS13DeriveSecret(AHash: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;
begin
  Result := TLS13DeriveSecretFromHash(AHash, ASecret, ALabel,
    TLS13TranscriptHash(AHash, ATranscript));
end;

function TLS13EarlySecret(AHash: THashKind; const APSK: TBytes): TBytes;
var
  IKM: TBytes;
begin
  if Length(APSK) = 0 then
    IKM := TLS13Zeros(AHash)
  else
    IKM := APSK;
  { An empty salt makes HKDF-Extract use HashLen zero bytes (RFC 5869,
     2.2), which is what the schedule prescribes. }
  Result := HKDFExtract(AHash, nil, IKM);
end;

function TLS13DerivedSecret(AHash: THashKind; const ASecret: TBytes): TBytes;
begin
  Result := TLS13DeriveSecret(AHash, ASecret, TLS13LabelDerived, nil);
end;

function TLS13HandshakeSecret(AHash: THashKind; const AEarlySecret,
  ADHESharedSecret: TBytes): TBytes;
begin
  Result := HKDFExtract(AHash, TLS13DerivedSecret(AHash, AEarlySecret),
    ADHESharedSecret);
end;

function TLS13MasterSecret(AHash: THashKind;
  const AHandshakeSecret: TBytes): TBytes;
begin
  Result := HKDFExtract(AHash, TLS13DerivedSecret(AHash, AHandshakeSecret),
    TLS13Zeros(AHash));
end;

function TLS13ClientHandshakeTrafficSecret(AHash: THashKind;
  const AHandshakeSecret, ATranscript: TBytes): TBytes;
begin
  Result := TLS13DeriveSecret(AHash, AHandshakeSecret,
    TLS13LabelClientHandshakeTraffic, ATranscript);
end;

function TLS13ServerHandshakeTrafficSecret(AHash: THashKind;
  const AHandshakeSecret, ATranscript: TBytes): TBytes;
begin
  Result := TLS13DeriveSecret(AHash, AHandshakeSecret,
    TLS13LabelServerHandshakeTraffic, ATranscript);
end;

function TLS13ClientApplicationTrafficSecret(AHash: THashKind;
  const AMasterSecret, ATranscript: TBytes): TBytes;
begin
  Result := TLS13DeriveSecret(AHash, AMasterSecret,
    TLS13LabelClientApplicationTraffic, ATranscript);
end;

function TLS13ServerApplicationTrafficSecret(AHash: THashKind;
  const AMasterSecret, ATranscript: TBytes): TBytes;
begin
  Result := TLS13DeriveSecret(AHash, AMasterSecret,
    TLS13LabelServerApplicationTraffic, ATranscript);
end;

function TLS13DeriveKeySchedule(AHash: THashKind; const APSK, ADHE: TBytes;
  const AHelloTranscript, AServerFinishedTranscript: TBytes)
  : TTLS13KeySchedule;
begin
  Result.HashKind := AHash;
  Result.HashLen := TLS13HashLen(AHash);
  Result.EarlySecret := TLS13EarlySecret(AHash, APSK);
  Result.HandshakeSecret := TLS13HandshakeSecret(AHash,
    Result.EarlySecret, ADHE);
  Result.ClientHandshakeTrafficSecret := TLS13ClientHandshakeTrafficSecret(
    AHash, Result.HandshakeSecret, AHelloTranscript);
  Result.ServerHandshakeTrafficSecret := TLS13ServerHandshakeTrafficSecret(
    AHash, Result.HandshakeSecret, AHelloTranscript);
  Result.MasterSecret := TLS13MasterSecret(AHash, Result.HandshakeSecret);
  Result.ClientApplicationTrafficSecret :=
    TLS13ClientApplicationTrafficSecret(AHash, Result.MasterSecret,
      AServerFinishedTranscript);
  Result.ServerApplicationTrafficSecret :=
    TLS13ServerApplicationTrafficSecret(AHash, Result.MasterSecret,
      AServerFinishedTranscript);
end;

{--- record layer (RFC 8446, 5) ------------------------------------------ }

function TLS13CipherSuiteAEADMode(ASuite: TTLSCipherSuite): TTLSAEADMode;
begin
  case ASuite of
    TLS13CipherAES128GCMSHA256:
      Result := aeadAES128GCM;
    TLS13CipherAES256GCMSHA384:
      Result := aeadAES256GCM;
    TLS13CipherChaCha20Poly1305SHA256:
      Result := aeadChaCha20Poly1305;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record layer: unsupported cipher suite 0x%.4X', [ASuite]);
  end;
end;

function TLS13CipherSuiteKeyLength(ASuite: TTLSCipherSuite): Integer;
begin
  { Rejects unsupported suites before the key length is chosen. }
  case TLS13CipherSuiteAEADMode(ASuite) of
    aeadAES128GCM:
      Result := 16;
    aeadAES256GCM, aeadChaCha20Poly1305:
      Result := 32;
  end;
end;

function TLS13DeriveRecordKeys(AHash: THashKind; ASuite: TTLSCipherSuite;
  const ASecret: TBytes): TTLS13RecordKeys;
begin
  Result.Key := HKDFExpandLabel(AHash, ASecret, TLS13LabelWriteKey, nil,
    TLS13CipherSuiteKeyLength(ASuite));
  Result.IV := HKDFExpandLabel(AHash, ASecret, TLS13LabelWriteIV, nil,
    TLS13RecordIVLen);
end;

function TLS13RecordNonce(const AIV: TBytes; ASeqNum: QWord): TBytes;
var
  I: Integer;
  Seq: QWord;
begin
  if Length(AIV) <> TLS13RecordIVLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record layer: the write IV must be %d bytes, got %d',
      [TLS13RecordIVLen, Length(AIV)]);
  SetLength(Result, TLS13RecordIVLen);
  Move(AIV[0], Result[0], TLS13RecordIVLen);
  { seq_num is a 64-bit big-endian value left-padded with zeros to the IV
    size, so it XORs only into the last 8 bytes of the 12-byte IV. }
  Seq := ASeqNum;
  for I := TLS13RecordIVLen - 1 downto TLS13RecordIVLen - 8 do
  begin
    Result[I] := Result[I] xor Byte(Seq and $FF);
    Seq := Seq shr 8;
  end;
end;

function TLS13RecordAdditionalData(ACiphertextLength: Integer): TBytes;
begin
  if (ACiphertextLength < 0) or (ACiphertextLength > High(Word)) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record layer: invalid ciphertext length %d',
      [ACiphertextLength]);
  SetLength(Result, 5);
  Result[0] := TLS13RecordOpaqueType;
  Result[1] := Byte(TLS13RecordLegacyVersion shr 8);
  Result[2] := Byte(TLS13RecordLegacyVersion and $FF);
  Result[3] := Byte(ACiphertextLength shr 8);
  Result[4] := Byte(ACiphertextLength and $FF);
end;

function TLS13ProtectRecordFragment(ASuite: TTLSCipherSuite;
  const AKey, AIV: TBytes; ASeqNum: QWord;
  const APlain: TBytes): TBytes;
var
  Mode: TTLSAEADMode;
  Nonce, AAD, Cipher, Tag: TBytes;
begin
  Mode := TLS13CipherSuiteAEADMode(ASuite);
  if Length(AKey) <> TLS13CipherSuiteKeyLength(ASuite) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record layer: suite 0x%.4X needs a %d-byte key, got %d',
      [ASuite, TLS13CipherSuiteKeyLength(ASuite), Length(AKey)]);
  Nonce := TLS13RecordNonce(AIV, ASeqNum);
  AAD := TLS13RecordAdditionalData(Length(APlain) + TLS13RecordTagLength);
  case Mode of
    aeadAES128GCM, aeadAES256GCM:
      AESGCMEncrypt(AKey, Nonce, AAD, APlain, Cipher, Tag);
    aeadChaCha20Poly1305:
      ChaCha20Poly1305Encrypt(AKey, Nonce, AAD, APlain, Cipher, Tag);
  end;
  Result := BytesConcat(Cipher, Tag);
end;

function TLS13UnprotectRecordFragment(ASuite: TTLSCipherSuite;
  const AKey, AIV: TBytes; ASeqNum: QWord;
  const AFragment: TBytes): TBytes;
var
  Mode: TTLSAEADMode;
  Nonce, AAD, Cipher, Tag: TBytes;
  Plain: TBytes;
  Len, Ok: Integer;
begin
  Mode := TLS13CipherSuiteAEADMode(ASuite);
  if Length(AKey) <> TLS13CipherSuiteKeyLength(ASuite) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record layer: suite 0x%.4X needs a %d-byte key, got %d',
      [ASuite, TLS13CipherSuiteKeyLength(ASuite), Length(AKey)]);
  Len := Length(AFragment);
  { The inner plaintext is at least the content-type byte, so a valid
    fragment holds at least TLS13RecordTagLength + 1 bytes. }
  if Len < TLS13RecordTagLength + 1 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record layer: encrypted record is too short (%d bytes)',
      [Len]);
  Cipher := Copy(AFragment, 0, Len - TLS13RecordTagLength);
  Tag := Copy(AFragment, Len - TLS13RecordTagLength, TLS13RecordTagLength);
  Nonce := TLS13RecordNonce(AIV, ASeqNum);
  AAD := TLS13RecordAdditionalData(Len);
  case Mode of
    aeadAES128GCM, aeadAES256GCM:
      Ok := Ord(AESGCMDecrypt(AKey, Nonce, AAD, Cipher, Tag, Plain));
    aeadChaCha20Poly1305:
      Ok := Ord(ChaCha20Poly1305Decrypt(AKey, Nonce, AAD, Cipher, Tag, Plain));
  end;
  if Ok = 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 record layer: record authentication failed');
  Result := Plain;
end;

{--- inner plaintext (RFC 8446, 5.2) ------------------------------------- }

{ Whether AContentType is one of the content types that may appear inside a
  protected record: alert, handshake or application_data. change_cipher_spec
  and unknown values must not be encrypted. }
function TLS13IsProtectedContentType(AContentType: Byte): Boolean;
begin
  Result := (AContentType = TLS13ContentAlert) or
    (AContentType = TLS13ContentHandshake) or
    (AContentType = TLS13ContentApplicationData);
end;

function TLS13InnerPlaintextLength(AContentLength, APadding: Integer): Integer;
begin
  if AContentLength < 0 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 inner plaintext: negative content length %d', [AContentLength]);
  if APadding < 0 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 inner plaintext: negative padding %d', [APadding]);
  Result := AContentLength + 1 + APadding;
  if Result > TLS13InnerPlaintextMaxLength then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 inner plaintext: %d bytes exceed the limit of %d',
      [Result, TLS13InnerPlaintextMaxLength]);
end;

function TLS13EncodeInnerPlaintext(AContentType: Byte;
  const AContent: TBytes; APadding: Integer): TBytes;
var
  ContentLen, Total: Integer;
begin
  if not TLS13IsProtectedContentType(AContentType) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 inner plaintext: content type %d must not be protected',
      [AContentType]);
  ContentLen := Length(AContent);
  Total := TLS13InnerPlaintextLength(ContentLen, APadding);
  SetLength(Result, Total);
  if ContentLen > 0 then
    Move(AContent[0], Result[0], ContentLen);
  Result[ContentLen] := AContentType;
  if APadding > 0 then
    FillChar(Result[ContentLen + 1], APadding, 0);
end;

function TLS13DecodeInnerPlaintext(const APlain: TBytes;
  out AContentType: Byte; out AContent: TBytes): Integer;
var
  I: Integer;
begin
  AContentType := 0;
  AContent := nil;
  if Length(APlain) = 0 then
    raise ETLS13Error.Create('TLS 1.3 inner plaintext: empty record');
  { Trailing zero bytes are padding; the last non-zero byte is the real
    content type and everything before it is the content. }
  I := Length(APlain) - 1;
  while (I >= 0) and (APlain[I] = 0) do
    Dec(I);
  if I < 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 inner plaintext: record consists of padding only');
  AContentType := APlain[I];
  if AContentType = TLS13ContentChangeCipherSpec then
    raise ETLS13Error.Create(
      'TLS 1.3 inner plaintext: change_cipher_spec must not be protected');
  if not TLS13IsProtectedContentType(AContentType) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 inner plaintext: unknown content type %d', [AContentType]);
  Result := Length(APlain) - 1 - I;
  if I > 0 then
    AContent := Copy(APlain, 0, I);
end;

{--- legacy ChangeCipherSpec (RFC 8446, 5) ------------------------------- }

function TLS13IsLegacyChangeCipherSpec(AType: TTLSContentType;
  const AFragment: TBytes): Boolean;
begin
  Result := (AType = ctChangeCipherSpec) and (Length(AFragment) = 1) and
    (AFragment[0] = TLSChangeCipherSpec);
end;

procedure TLS13CheckLegacyChangeCipherSpec(const AFragment: TBytes);
begin
  if (Length(AFragment) <> 1) or (AFragment[0] <> TLSChangeCipherSpec) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 legacy ChangeCipherSpec: expected byte 0x%02X, got %d bytes',
      [TLSChangeCipherSpec, Length(AFragment)]);
end;

{--- Finished (RFC 8446, 4.4.4) ------------------------------------------ }

function TLS13FinishedKey(AHash: THashKind; const ABaseKey: TBytes): TBytes;
begin
  if Length(ABaseKey) <> TLS13HashLen(AHash) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 Finished: base key is %d bytes, expected %d',
      [Length(ABaseKey), TLS13HashLen(AHash)]);
  { finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) }
  Result := HKDFExpandLabel(AHash, ABaseKey, TLS13LabelFinished, nil,
    TLS13HashLen(AHash));
end;

function TLS13VerifyDataFromHash(AHash: THashKind; const ABaseKey: TBytes;
  const ATranscriptHash: TBytes): TBytes;
var
  FinishedKey: TBytes;
begin
  FinishedKey := TLS13FinishedKey(AHash, ABaseKey);
  Result := THMAC.Compute(AHash, FinishedKey, ATranscriptHash);
end;

function TLS13VerifyData(AHash: THashKind; const ABaseKey: TBytes;
  const ATranscript: TBytes): TBytes;
begin
  Result := TLS13VerifyDataFromHash(AHash, ABaseKey,
    TLS13TranscriptHash(AHash, ATranscript));
end;

{ Comparison without early exit: the loop runs over the whole input, so the
  time does not reveal the position of the first differing byte. Only the
  (public) lengths may short-circuit. }
function TLS13ConstantTimeEquals(const A, B: TBytes): Boolean;
var
  I, N: Integer;
  Diff: Byte;
begin
  N := Length(A);
  if N <> Length(B) then
    Exit(False);
  Diff := 0;
  for I := 0 to N - 1 do
    Diff := Diff or (A[I] xor B[I]);
  Result := Diff = 0;
end;

function TLS13CheckVerifyDataFromHash(AHash: THashKind;
  const ABaseKey, ATranscriptHash, AVerifyData: TBytes): Boolean;
begin
  Result := TLS13ConstantTimeEquals(
    TLS13VerifyDataFromHash(AHash, ABaseKey, ATranscriptHash), AVerifyData);
end;

function TLS13CheckVerifyData(AHash: THashKind;
  const ABaseKey, ATranscript, AVerifyData: TBytes): Boolean;
begin
  Result := TLS13CheckVerifyDataFromHash(AHash, ABaseKey,
    TLS13TranscriptHash(AHash, ATranscript), AVerifyData);
end;

{ --- TTLS13Client ---------------------------------------------------- }

function TTLS13Client.GetHandshakeDone: Boolean;
begin
  Result := FHandshakeDone;
end;

function TTLS13Client.GetCipherSuite: TTLSCipherSuite;
begin
  Result := FCipherSuite;
end;

function TTLS13Client.GetPendingBytes: LongInt;
begin
  Result := Length(FRecvBuf) - FRecvPos;
  if Result < 0 then
    Result := 0;
end;

function TTLS13Client.CertChain: TTLS12CertChain;
begin
  Result := FChain;
end;

constructor TTLS13Client.Create;
begin
  inherited Create;
  FTransport := nil;
  FOptions := DefaultTLS13ClientHelloOptions;
  FKeyShares := nil;
  FOwnsKeyShares := False;
  FTrustStore := nil;
  FChain := nil;
  FConnected := False;
  FHandshakeDone := False;
  FStarted := False;
  FCipherSuite := 0;
  FHashKind := hkSHA256;
  FHandshakeSecret := nil;
  FMasterSecret := nil;
  FClientHandshakeTrafficSecret := nil;
  FServerHandshakeTrafficSecret := nil;
  FClientApplicationTrafficSecret := nil;
  FServerApplicationTrafficSecret := nil;
  FClientHandshakeKeys.Key := nil;
  FClientHandshakeKeys.IV := nil;
  FServerHandshakeKeys.Key := nil;
  FServerHandshakeKeys.IV := nil;
  FClientApplicationKeys.Key := nil;
  FClientApplicationKeys.IV := nil;
  FServerApplicationKeys.Key := nil;
  FServerApplicationKeys.IV := nil;
  FClientSeq := 0;
  FServerSeq := 0;
  FHandshakeData := nil;
  FTranscript := nil;
  FRecvBuf := nil;
  FRecvPos := 0;
end;

destructor TTLS13Client.Destroy;
begin
  if FChain <> nil then
    FChain.Free;
  { Key shares generated by the client are owned by it; offers supplied
    through Options are owned by the caller and must not be freed here. }
  if FOwnsKeyShares then
  begin
    TLS13KeyShareOffersFree(FKeyShares);
    FOptions.KeyShareOffers := nil;
  end;
  inherited Destroy;
end;

procedure TTLS13Client.PrepareClientHello;
begin
  if Length(FOptions.ClientRandom) = 0 then
    RandomBytes(FOptions.ClientRandom, TLS13ClientRandomLen)
  else if Length(FOptions.ClientRandom) <> TLS13ClientRandomLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 client: ClientHello random is %d bytes (expected %d)',
      [Length(FOptions.ClientRandom), TLS13ClientRandomLen]);

  if Length(FOptions.LegacySessionID) = 0 then
  begin
    if FOptions.CompatibilityMode then
      RandomBytes(FOptions.LegacySessionID, TLS13CompatSessionIDLen);
  end
  else if Length(FOptions.LegacySessionID) > TLS13CompatSessionIDLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 client: legacy_session_id is %d bytes (maximum %d)',
      [Length(FOptions.LegacySessionID), TLS13CompatSessionIDLen]);

  if Length(FOptions.CipherSuites) = 0 then
    FOptions.CipherSuites := TLS13DefaultCipherSuites;
  if Length(FOptions.SupportedGroups) = 0 then
    FOptions.SupportedGroups := TLS13DefaultSupportedGroups;
  if Length(FOptions.SignatureSchemes) = 0 then
    FOptions.SignatureSchemes := TLS13DefaultSignatureSchemes;

  if Length(FOptions.KeyShareOffers) = 0 then
  begin
    FKeyShares := TLS13GenerateKeyShareOffers(FOptions.SupportedGroups);
    FOwnsKeyShares := True;
    FOptions.KeyShareOffers := FKeyShares;
  end
  else
  begin
    FKeyShares := FOptions.KeyShareOffers;
    FOwnsKeyShares := False;
  end;
end;

function TTLS13Client.FindKeyShare(AGroup: Word): Integer;
var
  i: Integer;
begin
  for i := 0 to High(FKeyShares) do
    if FKeyShares[i].Entry.Group = AGroup then
      Exit(i);
  Result := -1;
end;

procedure TTLS13Client.AppendTranscript(AType: TTLSHandshakeType;
  const ABody: TBytes);
begin
  FTranscript := BytesConcat(FTranscript,
    EncodeTLSHandshakeMessage(AType, ABody));
end;

procedure TTLS13Client.AppendTranscriptMessage(
  const AMsg: TTLSHandshakeMessage);
begin
  AppendTranscript(AMsg.MsgType, AMsg.Body);
end;

function TTLS13Client.HasCompleteHandshakeMessage: Boolean;
var
  BodyLen: Integer;
begin
  Result := False;
  if Length(FHandshakeData) < TLSHandshakeHeaderLen then
    Exit;
  BodyLen := (Integer(FHandshakeData[1]) shl 16) or
    (Integer(FHandshakeData[2]) shl 8) or Integer(FHandshakeData[3]);
  Result := Length(FHandshakeData) >= TLSHandshakeHeaderLen + BodyLen;
end;

function TTLS13Client.TakeHandshakeMessage: TTLSHandshakeMessage;
var
  Consumed: Integer;
begin
  if not HasCompleteHandshakeMessage then
    raise ETLS13Error.Create(
      'TLS 1.3 client: no complete handshake message available');
  try
    Result := DecodeTLSHandshakeMessage(FHandshakeData, Consumed);
  except
    on E: ETLS12Error do
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 client: malformed handshake message: %s', [E.Message]);
  end;
  { Drop the consumed message; anything after it stays buffered so that
    several messages coalesced into one record are handled in order. }
  if Consumed < Length(FHandshakeData) then
    FHandshakeData := Copy(FHandshakeData, Consumed,
      Length(FHandshakeData) - Consumed)
  else
    FHandshakeData := nil;
end;

procedure TTLS13Client.ReadPlaintextHandshakeRecord;
var
  Rec: TTLSRecord;
  Alert: TTLSAlert;
begin
  Rec := ReadTLSRecord(FTransport);
  case Ord(Rec.ContentType) of
    TLS13ContentChangeCipherSpec:
      TLS13CheckLegacyChangeCipherSpec(Rec.Fragment);
    TLS13ContentHandshake:
      FHandshakeData := BytesConcat(FHandshakeData, Rec.Fragment);
    TLS13ContentAlert:
      begin
        Alert := DecodeTLSAlert(Rec.Fragment);
        raise ETLS13Error.CreateFmt(
          'TLS 1.3: server aborted the handshake with a %s alert (%s)',
          [TLSAlertLevelName(Alert.Level),
           TLSAlertDescriptionName(Alert.Description)]);
      end;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: unexpected record type %d during the handshake',
      [Ord(Rec.ContentType)]);
  end;
end;

procedure TTLS13Client.ReadProtectedHandshakeRecord;
var
  Rec: TTLSRecord;
  Plain, Content: TBytes;
  ContentType: Byte;
  Alert: TTLSAlert;
begin
  Rec := ReadTLSRecord(FTransport);
  case Ord(Rec.ContentType) of
    TLS13ContentChangeCipherSpec:
      begin
        { Middlebox compatibility CCS (RFC 8446, 5): drop and continue. }
        TLS13CheckLegacyChangeCipherSpec(Rec.Fragment);
        Exit;
      end;
    TLS13ContentAlert:
      begin
        Alert := DecodeTLSAlert(Rec.Fragment);
        raise ETLS13Error.CreateFmt(
          'TLS 1.3: server sent an unprotected %s alert during the '
          + 'handshake', [TLSAlertDescriptionName(Alert.Description)]);
      end;
    TLS13ContentApplicationData:
      begin end;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: unexpected record type %d during the handshake',
      [Ord(Rec.ContentType)]);
  end;

  { A protected record always carries application_data as the outer type
    and the real content type in the inner plaintext (RFC 8446, 5.2). }
  Plain := TLS13UnprotectRecordFragment(FCipherSuite,
    FServerHandshakeKeys.Key, FServerHandshakeKeys.IV, FServerSeq,
    Rec.Fragment);
  Inc(FServerSeq);
  TLS13DecodeInnerPlaintext(Plain, ContentType, Content);
  case ContentType of
    TLS13ContentHandshake:
      FHandshakeData := BytesConcat(FHandshakeData, Content);
    TLS13ContentAlert:
      begin
        Alert := DecodeTLSAlert(Content);
        raise ETLS13Error.CreateFmt(
          'TLS 1.3: server aborted the handshake with a %s alert (%s)',
          [TLSAlertLevelName(Alert.Level),
           TLSAlertDescriptionName(Alert.Description)]);
      end;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: unexpected inner content type %d during the handshake',
      [ContentType]);
  end;
end;

function TTLS13Client.NextProtectedHandshakeMessage: TTLSHandshakeMessage;
begin
  while not HasCompleteHandshakeMessage do
    ReadProtectedHandshakeRecord;
  Result := TakeHandshakeMessage;
end;

procedure TTLS13Client.HandlePostHandshakeHandshake(const AData: TBytes);
var
  Rest: TBytes;
  Msg: TTLSHandshakeMessage;
  Consumed: Integer;
begin
  Rest := AData;
  while Length(Rest) > 0 do
  begin
    if Length(Rest) < TLSHandshakeHeaderLen then
      raise ETLS13Error.Create(
        'TLS 1.3: truncated post-handshake message');
    try
      Msg := DecodeTLSHandshakeMessage(Rest, Consumed);
    except
      on E: ETLS12Error do
        raise ETLS13Error.CreateFmt(
          'TLS 1.3: malformed post-handshake message: %s', [E.Message]);
    end;
    case Msg.MsgType of
      htNewSessionTicket:
        begin end;  { no resumption support: tickets are ignored }
      htKeyUpdate:
        raise ETLS13Error.Create(
          'TLS 1.3: server requested a KeyUpdate, which is not supported');
    else
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: unexpected post-handshake message %s',
        [TLSHandshakeTypeName(Msg.MsgType)]);
    end;
    Rest := Copy(Rest, Consumed, Length(Rest) - Consumed);
  end;
end;

{ Parses the CertificateVerify body (RFC 8446, 4.4.3):

    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;

  Local to the client: no other code needs the raw pair yet, and keeping
  the parser here leaves the public API limited to the verification
  helpers. An empty signature and a length that does not match the body
  are rejected with ETLS13Error. }
procedure TLS13ParseCertificateVerifyBody(const ABody: TBytes;
  out AScheme: TTLSSignatureScheme; out ASignature: TBytes);
var
  SigLen: Integer;
begin
  AScheme := 0;
  ASignature := nil;
  if Length(ABody) < 4 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 CertificateVerify: body is %d bytes (expected at least 4)',
      [Length(ABody)]);
  AScheme := (TTLSSignatureScheme(ABody[0]) shl 8) or
    TTLSSignatureScheme(ABody[1]);
  SigLen := (Integer(ABody[2]) shl 8) or Integer(ABody[3]);
  if Length(ABody) <> 4 + SigLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 CertificateVerify: signature length %d does not match the '
      + '%d-byte body', [SigLen, Length(ABody)]);
  if SigLen = 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 CertificateVerify: empty signature');
  ASignature := Copy(ABody, 4, SigLen);
end;

{ Verifies a CertificateVerify signature with the leaf certificate,
  dispatching on the scheme. Only the schemes advertised in the
  ClientHello (TLS13SignatureSchemeSupported) reach a verifier, so an
  RSA PKCS#1 v1.5, Ed25519 or unknown scheme is rejected without being
  interpreted as ECDSA or RSA-PSS. }
function TLS13VerifyCertificateVerifySignature(const ACert: TX509Cert;
  AScheme: TTLSSignatureScheme;
  const AContent, ASignature: TBytes): Boolean;
begin
  if not TLS13SignatureSchemeSupported(AScheme) then
    Exit(False);
  if (AScheme = TLSSigECDSA_Secp256r1_SHA256) or
    (AScheme = TLSSigECDSA_Secp384r1_SHA384) then
    Result := VerifyTLS13ECDSASignature(ACert, AScheme, AContent, ASignature)
  else
    Result := VerifyTLS13RSAPSSSignature(ACert, AScheme, AContent,
      ASignature);
end;

procedure TTLS13Client.DoHandshake;
var
  HelloBody, DHE, HelloTranscript, ServerFinishedTranscript: TBytes;
  Msg: TTLSHandshakeMessage;
  SH: TTLS13ServerHello;
  VR: TVerifyResult;
  Index: Integer;
  Scheme: TTLSSignatureScheme;
  Signature, Content, ClientVD, ClientFinished: TBytes;
  Inner, Fragment: TBytes;
begin
  FHandshakeData := nil;
  FTranscript := nil;
  FRecvBuf := nil;
  FRecvPos := 0;
  FClientSeq := 0;
  FServerSeq := 0;
  FHandshakeDone := False;

  { --- ClientHello, followed by a compatibility CCS when a non-empty
    legacy_session_id was sent (RFC 8446, Appendix D.4). --- }
  try
    PrepareClientHello;
    HelloBody := BuildTLS13ClientHelloBody(FOptions);
  except
    on E: ETLS13Error do
      raise;
    on E: Exception do
      raise ETLS13Error.CreateFmt('TLS 1.3 ClientHello: %s', [E.Message]);
  end;
  WriteTLS13ClientHello(FTransport, FOptions);
  AppendTranscript(htClientHello, HelloBody);
  if Length(FOptions.LegacySessionID) > 0 then
    WriteTLSRecord(FTransport, ctChangeCipherSpec,
      EncodeTLSChangeCipherSpec, TLS13RecordLegacyVersion);

  { --- ServerHello: the only unprotected handshake message. --- }
  while not HasCompleteHandshakeMessage do
    ReadPlaintextHandshakeRecord;
  Msg := TakeHandshakeMessage;
  if Msg.MsgType <> htServerHello then
    raise ETLS13Error.CreateFmt('TLS 1.3: expected ServerHello, got %s',
      [TLSHandshakeTypeName(Msg.MsgType)]);
  SH := ParseTLS13ServerHello(Msg.Body, FOptions.LegacySessionID);
  if Length(FHandshakeData) > 0 then
    raise ETLS13Error.Create(
      'TLS 1.3: unexpected plaintext handshake data after ServerHello');
  AppendTranscriptMessage(Msg);

  FCipherSuite := SH.CipherSuite;
  FHashKind := TLS13CipherSuiteHashKind(FCipherSuite);

  { --- (EC)DHE shared secret from the offered key share. --- }
  Index := FindKeyShare(SH.KeyShare.Group);
  if Index < 0 then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: server selected key_share group %d, which was not offered',
      [SH.KeyShare.Group]);
  try
    DHE := TLS13KeyShareSecret(FKeyShares[Index].KeyShare,
      SH.KeyShare.KeyExchange);
  except
    on E: ETLS13Error do
      raise;
    on E: Exception do
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: cannot compute the (EC)DHE shared secret: %s',
        [E.Message]);
  end;

  { --- Key schedule: handshake secrets and their record keys. --- }
  FHandshakeSecret := TLS13HandshakeSecret(FHashKind,
    TLS13EarlySecret(FHashKind, nil), DHE);
  HelloTranscript := FTranscript;
  FClientHandshakeTrafficSecret := TLS13ClientHandshakeTrafficSecret(
    FHashKind, FHandshakeSecret, HelloTranscript);
  FServerHandshakeTrafficSecret := TLS13ServerHandshakeTrafficSecret(
    FHashKind, FHandshakeSecret, HelloTranscript);
  FMasterSecret := TLS13MasterSecret(FHashKind, FHandshakeSecret);
  FClientHandshakeKeys := TLS13DeriveRecordKeys(FHashKind, FCipherSuite,
    FClientHandshakeTrafficSecret);
  FServerHandshakeKeys := TLS13DeriveRecordKeys(FHashKind, FCipherSuite,
    FServerHandshakeTrafficSecret);
  FServerSeq := 0;

  { --- EncryptedExtensions. --- }
  Msg := NextProtectedHandshakeMessage;
  if Msg.MsgType <> htEncryptedExtensions then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: expected EncryptedExtensions, got %s',
      [TLSHandshakeTypeName(Msg.MsgType)]);
  ParseTLS13EncryptedExtensionsMessage(Msg);
  AppendTranscriptMessage(Msg);

  { --- Certificate. --- }
  Msg := NextProtectedHandshakeMessage;
  if Msg.MsgType = htCertificateRequest then
    raise ETLS13Error.Create(
      'TLS 1.3: the server requested client authentication, which is not '
      + 'supported');
  if Msg.MsgType <> htCertificate then
    raise ETLS13Error.CreateFmt('TLS 1.3: expected Certificate, got %s',
      [TLSHandshakeTypeName(Msg.MsgType)]);
  if FChain <> nil then
    FChain.Free;
  FChain := TLS13CertificateChain(ParseTLS13CertificateMessage(Msg));
  AppendTranscriptMessage(Msg);
  if FChain.Count = 0 then
    raise ETLS13Error.Create('TLS 1.3: the server sent no certificate');
  if FTrustStore <> nil then
  begin
    VR := FChain.Verify(FTrustStore);
    if not VR.OK then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: certificate chain verification failed: %s', [VR.Reason]);
  end;

  { --- CertificateVerify. --- }
  Msg := NextProtectedHandshakeMessage;
  if Msg.MsgType <> htCertificateVerify then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: expected CertificateVerify, got %s',
      [TLSHandshakeTypeName(Msg.MsgType)]);
  TLS13ParseCertificateVerifyBody(Msg.Body, Scheme, Signature);
  { A scheme this client never advertised must be rejected explicitly,
    instead of surfacing later as a generic "signature is invalid". }
  if not TLS13SignatureSchemeSupported(Scheme) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: server selected unsupported signature scheme 0x%.4X '
      + '(only ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 and '
      + 'rsa_pss_rsae_sha256 are verifiable)', [Scheme]);
  Content := TLS13CertificateVerifyContent(
    TLS13ContextStringServerCertificateVerify,
    TLS13TranscriptHash(FHashKind, FTranscript));
  if not TLS13VerifyCertificateVerifySignature(FChain.Leaf, Scheme, Content,
    Signature) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: CertificateVerify signature (scheme 0x%.4X) is invalid',
      [Scheme]);
  AppendTranscriptMessage(Msg);

  { --- Server Finished: verified against the transcript through
    CertificateVerify (the Finished itself is not covered). --- }
  Msg := NextProtectedHandshakeMessage;
  if Msg.MsgType <> htFinished then
    raise ETLS13Error.CreateFmt('TLS 1.3: expected Finished, got %s',
      [TLSHandshakeTypeName(Msg.MsgType)]);
  if not TLS13CheckVerifyData(FHashKind, FServerHandshakeTrafficSecret,
    FTranscript, Msg.Body) then
    raise ETLS13Error.Create(
      'TLS 1.3: server Finished verify_data mismatch');
  AppendTranscriptMessage(Msg);
  ServerFinishedTranscript := FTranscript;

  { --- Application secrets; the receive side switches keys here. --- }
  FClientApplicationTrafficSecret := TLS13ClientApplicationTrafficSecret(
    FHashKind, FMasterSecret, ServerFinishedTranscript);
  FServerApplicationTrafficSecret := TLS13ServerApplicationTrafficSecret(
    FHashKind, FMasterSecret, ServerFinishedTranscript);
  FClientApplicationKeys := TLS13DeriveRecordKeys(FHashKind, FCipherSuite,
    FClientApplicationTrafficSecret);
  FServerApplicationKeys := TLS13DeriveRecordKeys(FHashKind, FCipherSuite,
    FServerApplicationTrafficSecret);
  FServerSeq := 0;

  { --- Client Finished: the last message under the handshake keys. --- }
  ClientVD := TLS13VerifyData(FHashKind, FClientHandshakeTrafficSecret,
    FTranscript);
  ClientFinished := EncodeTLSHandshakeMessage(htFinished, ClientVD);
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentHandshake, ClientFinished);
  Fragment := TLS13ProtectRecordFragment(FCipherSuite,
    FClientHandshakeKeys.Key, FClientHandshakeKeys.IV, FClientSeq, Inner);
  Inc(FClientSeq);
  WriteTLSRecord(FTransport, ctApplicationData, Fragment,
    TLS13RecordLegacyVersion);

  { From here on the client sends with the application keys; the sequence
    number of the new key set starts at zero (RFC 8446, 5.3). }
  FClientSeq := 0;
  FHandshakeDone := True;
end;

procedure TTLS13Client.Connect(ATransport: ITLSTransport);
begin
  if FStarted or FHandshakeDone then
    raise ETLS13Error.Create(
      'TLS 1.3: the client is single-use (Connect was already called)');
  if ATransport = nil then
    raise ETLS13Error.Create('TLS 1.3: transport is nil');
  FStarted := True;
  FTransport := ATransport;
  FConnected := True;
  try
    DoHandshake;
  except
    on E: ETLS13Error do
    begin
      FConnected := False;
      raise;
    end;
    on E: ETLS12Error do
    begin
      { Failures coming from the shared record/handshake layer (transport
        errors, truncation) are reported as TLS 1.3 errors. }
      FConnected := False;
      raise ETLS13Error.Create(E.Message);
    end;
    on E: Exception do
    begin
      FConnected := False;
      raise;
    end;
  end;
end;

procedure TTLS13Client.Send(const AData: TBytes);
var
  Offset, Total, Chunk: Integer;
  Part, Inner, Fragment: TBytes;
begin
  if not FHandshakeDone then
    raise ETLS13Error.Create('TLS 1.3: Send before the handshake completed');
  Total := Length(AData);
  if Total = 0 then
    Exit;
  Offset := 0;
  while Offset < Total do
  begin
    Chunk := Total - Offset;
    if Chunk > TLSRecordMaxPayload then
      Chunk := TLSRecordMaxPayload;
    Part := Copy(AData, Offset, Chunk);
    Inner := TLS13EncodeInnerPlaintext(TLS13ContentApplicationData, Part);
    Fragment := TLS13ProtectRecordFragment(FCipherSuite,
      FClientApplicationKeys.Key, FClientApplicationKeys.IV, FClientSeq,
      Inner);
    Inc(FClientSeq);
    WriteTLSRecord(FTransport, ctApplicationData, Fragment,
      TLS13RecordLegacyVersion);
    Inc(Offset, Chunk);
  end;
end;

function TTLS13Client.Recv(var ABuffer; ACount: LongInt): LongInt;
var
  Rec: TTLSRecord;
  Plain, Content: TBytes;
  ContentType: Byte;
  Alert: TTLSAlert;
  Avail, ToCopy: LongInt;
begin
  if not FHandshakeDone then
    raise ETLS13Error.Create('TLS 1.3: Recv before the handshake completed');
  if ACount <= 0 then
    Exit(0);

  Result := 0;
  while True do
  begin
    { Return buffered plaintext first. }
    Avail := GetPendingBytes;
    if Avail > 0 then
    begin
      ToCopy := Avail;
      if ToCopy > ACount then
        ToCopy := ACount;
      Move(FRecvBuf[FRecvPos], ABuffer, ToCopy);
      Inc(FRecvPos, ToCopy);
      if FRecvPos >= Length(FRecvBuf) then
      begin
        FRecvBuf := nil;
        FRecvPos := 0;
      end;
      Exit(ToCopy);
    end;

    { Read the next record. }
    try
      Rec := ReadTLSRecord(FTransport);
    except
      on E: ETLS12Error do
        Exit(0);  { transport closed or failed: signal EOF }
    end;

    case Ord(Rec.ContentType) of
      TLS13ContentChangeCipherSpec:
        begin
          TLS13CheckLegacyChangeCipherSpec(Rec.Fragment);
          Continue;
        end;
      TLS13ContentAlert:
        begin
          { Alerts sent after the handshake must be protected; a bare one
            is a protocol violation. }
          Alert := DecodeTLSAlert(Rec.Fragment);
          raise ETLS13Error.CreateFmt(
            'TLS 1.3: server sent an unprotected alert after the handshake '
            + '(%s)', [TLSAlertDescriptionName(Alert.Description)]);
        end;
      TLS13ContentApplicationData:
        begin end;
    else
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: unexpected record type %d after the handshake',
        [Ord(Rec.ContentType)]);
    end;

    Plain := TLS13UnprotectRecordFragment(FCipherSuite,
      FServerApplicationKeys.Key, FServerApplicationKeys.IV, FServerSeq,
      Rec.Fragment);
    Inc(FServerSeq);
    TLS13DecodeInnerPlaintext(Plain, ContentType, Content);

    case ContentType of
      TLS13ContentApplicationData:
        begin
          FRecvBuf := Content;
          FRecvPos := 0;
        end;
      TLS13ContentAlert:
        begin
          Alert := DecodeTLSAlert(Content);
          if Alert.Description = adCloseNotify then
            Exit(0);  { normal closure }
          if not TLS12AlertIsFatal(Alert) then
            Continue;  { ignore warning alerts other than close_notify }
          raise ETLS13Error.CreateFmt(
            'TLS 1.3: fatal alert from server: %s',
            [TLSAlertDescriptionName(Alert.Description)]);
        end;
      TLS13ContentHandshake:
        HandlePostHandshakeHandshake(Content);
    else
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: unexpected inner content type %d after the handshake',
        [ContentType]);
    end;
  end;
end;

procedure TTLS13Client.Shutdown;
var
  Alert, Inner, Fragment: TBytes;
begin
  if not FConnected then
    Exit;
  if FHandshakeDone then
  begin
    { close_notify is a warning alert protected with the application
      traffic keys (RFC 8446, 6). }
    Alert := EncodeTLSAlert(alWarning, adCloseNotify);
    Inner := TLS13EncodeInnerPlaintext(TLS13ContentAlert, Alert);
    Fragment := TLS13ProtectRecordFragment(FCipherSuite,
      FClientApplicationKeys.Key, FClientApplicationKeys.IV, FClientSeq,
      Inner);
    Inc(FClientSeq);
    WriteTLSRecord(FTransport, ctApplicationData, Fragment,
      TLS13RecordLegacyVersion);
  end;
  FConnected := False;
  FHandshakeDone := False;
end;

procedure TTLS13Client.Close;
begin
  FConnected := False;
  FHandshakeDone := False;
end;

end.
