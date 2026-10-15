{ SPDX-License-Identifier: Apache-2.0 }
unit tls.tls12;

{TLS 1.2 client (RFC 5246) for task 12 (docs/tasks/12-tls12.md).

  Milestone D. Implemented:
    - basic TLS 1.2 constants (version 0x0303, record types, fragment
      limit 2^14);
    - ITLSTransport interface (Read/Write/BytesAvailable) — so that
      the record layer and handshake do not depend on the socket directly;
    - TTLSStreamTransport adapter over TStream (for tests and mocks);
    - record layer (RFC 5246, 6.2): assembly and parsing of records
      (type/version/length/fragment), reading/writing one and multiple
      fragments via the transport, enforcing the 2^14 byte limit;
    - AEAD record encryption (RFC 5288 AES-GCM, RFC 7905
      ChaCha20-Poly1305): AAD, nonce, encryption/decryption of
      fragments with tag verification;
    - handshake messages (RFC 5246, 7.4): header msg_type||length(3),
      assembly/parsing of a message and a flight (sequence of messages),
      TTLSHandshakeBuffer — assembly of messages split across multiple
      records, with transcript accumulation for Finished;
    - ClientHello (RFC 5246, 7.4.1.2; RFC 6066/5746/7627/7919):
      assembly/parsing, extensions SNI, supported_groups,
      signature_algorithms, EMS, renegotiation_info, SCSV;
    - parsing of the server flight: ServerHello (RFC 5246, 7.4.1.3),
      Certificate (7.4.2), ServerKeyExchange (7.4.3; ECDHE/DHE,
      RFC 4492) and ServerHelloDone (7.4.5);
    - ClientKeyExchange (RFC 5246, 7.4.7; RFC 4492, 5.7): ephemeral
      client keys for ECDHE P-256/P-384 and DHE, assembly/parsing of the body,
      computation of the premaster secret.

    - verification of the server flight: verification of the ServerKeyExchange
      signature with the public key of the server certificate and building/verification of the
      certificate chain against the trusted store (RFC 5280);
      parsing of DER certificates from the Certificate message.

   Subsequent steps will add CCS/Finished. }

{$mode objfpc}{$H+}

interface
uses
  SysUtils, Classes, tls.bn, tls.ec, tls.dh,
  tls.sha2, tls.hmac, tls.x509, tls.certstore;

const
  {TLS 1.2 protocol version on the wire: 0x0303. }
  TLS12VersionMajor = 3;
  TLS12VersionMinor = 3;
  TLS12Version = (TLS12VersionMajor shl 8) or TLS12VersionMinor;

  {Maximum payload length of a single TLS record (RFC 5246,
     6.2.1): a fragment cannot be longer than 2^14 bytes. }
  TLSRecordMaxPayload = 1 shl 14;
  {Maximum length of an encrypted fragment (RFC 5246, 6.2.3):
     2^14 + 2048 bytes (expansion for block ciphers / AEAD tag). }
  TLSRecordMaxCiphertext = (1 shl 14) + 2048;
  {Record header: type(1) + version(2) + length(2). }
  TLSRecordHeaderLen = 5;

  {AEAD (RFC 5288 AES-GCM, RFC 7905 ChaCha20-Poly1305): authentication
    tag length. }
  TLSAEADTagLen = 16;
  {AES-GCM: length of fixed_iv (write_IV) and explicit nonce in the record. }
  TLSGCMFixedIvLen = 4;
  TLSGCMExplicitNonceLen = 8;
  {ChaCha20-Poly1305: length of fixed_iv (write_IV). }
  TLSChaCha20FixedIvLen = 12;

  {Convention for return codes of ITLSTransport methods. }
  TLSTransportError = -1;   {error/timeout }
  TLSTransportEOF = 0;      {normal stream closure }
  {Handshake message header: msg_type(1) || length(3). }
  TLSHandshakeHeaderLen = 4;
  {Maximum length of a handshake message body: 2^24 - 1 (RFC 5246, 7.4). }
  TLSHandshakeMaxLength = (1 shl 24) - 1;
  {--- ClientHello: cipher suites, groups, signatures, extensions ------- }

  {Cipher suite identifiers (RFC 5246 A.4, RFC 5289, RFC 7905). }
  TLSCipherEmptyRenegotiationInfoSCSV = $00FF; { TLS_EMPTY_RENEGOTIATION_INFO_SCSV }
  TLSCipherFallbackSCSV = $5600;               { TLS_FALLBACK_SCSV }
  TLSCipherRSA_AES128GCM_SHA256 = $009C;
  TLSCipherRSA_AES256GCM_SHA384 = $009D;
  TLSCipherDHE_RSA_AES128GCM_SHA256 = $009E;
  TLSCipherDHE_RSA_AES256GCM_SHA384 = $009F;
  TLSCipherECDHE_ECDSA_AES128GCM_SHA256 = $C02B;
  TLSCipherECDHE_ECDSA_AES256GCM_SHA384 = $C02C;
  TLSCipherECDHE_RSA_AES128GCM_SHA256 = $C02F;
  TLSCipherECDHE_RSA_AES256GCM_SHA384 = $C030;
  TLSCipherECDHE_RSA_CHACHA20POLY1305_SHA256 = $CCA8;
  TLSCipherECDHE_ECDSA_CHACHA20POLY1305_SHA256 = $CCA9;

  {CBC and static-RSA suites (RFC 5246 A.5/A.6, RFC 4492 A.5): recognized
    by name for diagnostics, but NOT supported by this implementation.
    The record layer supports only AEAD (AES-GCM/ChaCha20-Poly1305), and key
    exchange is only ephemeral (EC)DHE; encryption of the key with static
    RSA (key transport) is not implemented. See TLS12CipherSuiteSupported. }
  TLSCipherRSA_3DES_EDE_CBC_SHA = $000A;        { TLS_RSA_WITH_3DES_EDE_CBC_SHA }
  TLSCipherRSA_RC4_128_SHA = $0005;             { TLS_RSA_WITH_RC4_128_SHA }
  TLSCipherRSA_AES128CBC_SHA = $002F;           { TLS_RSA_WITH_AES_128_CBC_SHA }
  TLSCipherDHE_RSA_AES128CBC_SHA = $0033;       { TLS_DHE_RSA_WITH_AES_128_CBC_SHA }
  TLSCipherRSA_AES256CBC_SHA = $0035;           { TLS_RSA_WITH_AES_256_CBC_SHA }
  TLSCipherDHE_RSA_AES256CBC_SHA = $0039;       { TLS_DHE_RSA_WITH_AES_256_CBC_SHA }
  TLSCipherRSA_AES128CBC_SHA256 = $003C;        { TLS_RSA_WITH_AES_128_CBC_SHA256 }
  TLSCipherRSA_AES256CBC_SHA256 = $003D;        { TLS_RSA_WITH_AES_256_CBC_SHA256 }
  TLSCipherECDHE_ECDSA_AES128CBC_SHA = $C009;   { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA }
  TLSCipherECDHE_ECDSA_AES256CBC_SHA = $C00A;   { TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA }
  TLSCipherECDHE_RSA_AES128CBC_SHA = $C013;     { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA }
  TLSCipherECDHE_RSA_AES256CBC_SHA = $C014;     { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA }

  {Extension identifiers (RFC 5246/6066/7627/7919/8422/5746). }
  TLSExtServerName = 0;
  TLSExtSupportedGroups = 10;   {also known as elliptic_curves, RFC 4492/7919 }
  TLSExtSignatureAlgorithms = 13;
  TLSExtExtendedMasterSecret = 23;
  TLSExtRenegotiationInfo = $FF01;
  TLSExtSessionTicket = 35;

  {Named groups (RFC 4492/7919): NIST curves, X25519/X448, FFDHE. }
  TLSNamedGroupSecp256r1 = $0017;
  TLSNamedGroupSecp384r1 = $0018;
  TLSNamedGroupSecp521r1 = $0019;
  TLSNamedGroupX25519 = $001D;
  TLSNamedGroupX448 = $001E;
  TLSNamedGroupFFDHE2048 = $0100;
  TLSNamedGroupFFDHE3072 = $0101;
  TLSNamedGroupFFDHE4096 = $0102;
  TLSNamedGroupFFDHE6144 = $0103;
  TLSNamedGroupFFDHE8192 = $0104;

  {Signature schemes (RFC 5246/8422; values rsa_pss/ed25519 — RFC 8446). }
  TLSSigRSA_PKCS1_SHA256 = $0401;
  TLSSigRSA_PKCS1_SHA384 = $0501;
  TLSSigRSA_PKCS1_SHA512 = $0601;
  TLSSigECDSA_Secp256r1_SHA256 = $0403;
  TLSSigECDSA_Secp384r1_SHA384 = $0503;
  TLSSigECDSA_Secp521r1_SHA512 = $0603;
  TLSSigRSA_PSS_RSAE_SHA256 = $0804;
  TLSSigRSA_PSS_RSAE_SHA384 = $0805;
  TLSSigRSA_PSS_RSAE_SHA512 = $0806;
  TLSSigEd25519 = $0807;

  {ClientHello field lengths/limits (RFC 5246, 7.4.1.2).}
  TLSClientRandomLen = 32;
  TLSMaxSessionIDLen = 32;
  TLSMaxCipherSuitesLen = $FFFE; {2-byte length, even number}
  TLSServerNameTypeHostName = 0;

  { ECCurveType (RFC 4492, 5.4). }
  TLSNamedCurveTypeExplicitPrime = 1;
  TLSNamedCurveTypeExplicitChar2 = 2;
  TLSNamedCurveTypeNamedCurve = 3;

  {SignatureAndHashAlgorithm wire size (TLS 1.2).}
  TLSSignatureSchemeLen = 2;

  {Maximum length of the Certificate certificate list (3-byte length).}
  TLSMaxCertificateListLen = (1 shl 24) - 1;

  {ChangeCipherSpec (RFC 5246, 7.1): a single message with a single
    0x01 byte, after which the negotiated cipher is enabled.}
  TLSChangeCipherSpec = 1;

  {Finished (RFC 5246, 7.4.9): verify_data in TLS 1.2 is 12 bytes.
    PRF labels for "client finished" and "server finished".}
  TLSFinishedVerifyDataLen = 12;
  TLSFinishedLabelClient = 'client finished';
  TLSFinishedLabelServer = 'server finished';

  {Alert (RFC 5246, 7.2): warning/error levels.}
  TLSAlertLevelWarning = 1;
  TLSAlertLevelFatal = 2;

type
  {TLS record content type (RFC 5246, 6.2.1).}
  TTLSContentType = (ctChangeCipherSpec = 20, ctAlert = 21,
    ctHandshake = 22, ctApplicationData = 23);

  {Parsed TLS record header (5 bytes).}
  TTLSRecordHeader = record
    ContentType: TTLSContentType;
    Version: Word;
    Length: Word;
  end;

  {Parsed TLS record: type, version, and fragment without MAC/IV.}
  TTLSRecord = record
    ContentType: TTLSContentType;
    Version: Word;
    Fragment: TBytes;
  end;

  {AEAD record encryption mode for TLS 1.2 (RFC 5288 AES-GCM,
    RFC 7905 ChaCha20-Poly1305).}
  TTLSAEADMode = (aeadAES128GCM, aeadAES256GCM, aeadChaCha20Poly1305);

  {--- Handshake messages (RFC 5246, 7.4) ---}

  {TLS handshake message type. Values are from RFC 5246 (7.4); added
    RFC 6066 messages (certificate_status, supplemental_data) and TLS 1.3
    (encrypted_extensions, key_update, message_hash) so parsing does not fail
    on an unknown type.}
  TTLSHandshakeType = (
    htHelloRequest = 0,
    htClientHello = 1,
    htServerHello = 2,
    htNewSessionTicket = 4,
    htEndOfEarlyData = 5,
    htEncryptedExtensions = 8,
    htCertificate = 11,
    htServerKeyExchange = 12,
    htCertificateRequest = 13,
    htServerHelloDone = 14,
    htCertificateVerify = 15,
    htClientKeyExchange = 16,
    htFinished = 20,
    htCertificateStatus = 22,
    htSupplementalData = 23,
    htKeyUpdate = 24,
    htMessageHash = 254);

  {Parsed 4-byte handshake message header:
      msg_type(1) || length(3, big-endian).
    Length is the message body length (without header), 0..2^24-1.}
  TTLSHandshakeHeader = record
    MsgType: TTLSHandshakeType;
    Length: Integer;
  end;

  {Full handshake message: type and body (without header).}
  TTLSHandshakeMessage = record
    MsgType: TTLSHandshakeType;
    Body: TBytes;
  end;

  {Sequence of handshake messages (flight/set).}
  TTLSHandshakeMessages = array of TTLSHandshakeMessage;
  TTLSHandshakeTypeSet = set of TTLSHandshakeType;
  { --- ClientHello (RFC 5246, 7.4.1.2; RFC 6066/5746/7627/7919) --- }

  {Cipher suite identifier (2 bytes on the wire).}
  TTLSCipherSuite = Word;
  TTLSCipherSuites = array of TTLSCipherSuite;

  {Named group identifier (named_group / NamedCurve).}
  TTLSNamedGroup = Word;
  TTLSNamedGroups = array of TTLSNamedGroup;

  {Signature scheme identifier (SignatureAndHashAlgorithm).}
  TTLSSignatureScheme = Word;
  TTLSSignatureSchemes = array of TTLSSignatureScheme;

  {ServerName entry from the SNI extension (RFC 6066).}
  TTLSServerName = record
    NameType: Byte;
    HostName: string;
  end;
  TTLSServerNames = array of TTLSServerName;

  {One ClientHello extension: type(2) || length(2) || data.}
  TTLSExtension = record
    ExtType: Word;
    Data: TBytes;
  end;
  TTLSExtensions = array of TTLSExtension;

  {ClientHello build options. Empty CipherSuites/SupportedGroups/
    SignatureAlgorithms are replaced with defaults.}
  TTLSClientHelloOptions = record
    ServerName: string;                {SNI; empty — extension is not sent}
    SessionID: TBytes;                 {0..32 bytes (nil — empty)}
    ClientRandom: TBytes;              {nil — generate 32 bytes}
    CipherSuites: TTLSCipherSuites;
    SupportedGroups: TTLSNamedGroups;  {aka elliptic_curves}
    SignatureAlgorithms: TTLSSignatureSchemes;
    ExtendedMasterSecret: Boolean;     {extension 23 (RFC 7627)}
    RenegotiationInfo: Boolean;        {renegotiation_info extension}
    RenegotiationInfoData: TBytes;     {RI contents (empty for the 1st handshake)}
    EmptyRenegotiationInfoSCSV: Boolean; {add SCSV 0x00FF}
    FallbackSCSV: Boolean;             {add TLS_FALLBACK_SCSV}
  end;

  {Parsed ClientHello (message body).}
  TTLSClientHello = record
    Version: Word;
    ClientRandom: TBytes;
    SessionID: TBytes;
    CipherSuites: TTLSCipherSuites;
    CompressionMethods: TBytes;
    Extensions: TTLSExtensions;
    ServerName: string;
    SupportedGroups: TTLSNamedGroups;
    SignatureAlgorithms: TTLSSignatureSchemes;
    ExtendedMasterSecret: Boolean;
    RenegotiationInfo: Boolean;
    RenegotiationInfoData: TBytes;
    EmptyRenegotiationInfoSCSV: Boolean;
    FallbackSCSV: Boolean;
  end;

  { --- ServerHello (RFC 5246, 7.4.1.3) --- }

  {Parsed ServerHello (message body) with derived fields from
    extensions.}
  TTLSServerHello = record
    Version: Word;
    ServerRandom: TBytes;              {32 bytes}
    SessionID: TBytes;                 {0..32 bytes}
    CipherSuite: TTLSCipherSuite;
    CompressionMethod: Byte;
    Extensions: TTLSExtensions;
    ExtendedMasterSecret: Boolean;     {extension 23 (RFC 7627)}
    RenegotiationInfo: Boolean;        {renegotiation_info extension}
    RenegotiationInfoData: TBytes;     { renegotiated_connection }
    ServerNameAcknowledged: Boolean;   {server_name extension (empty)}
    SessionTicket: Boolean;            {session_ticket extension}
    SessionTicketData: TBytes;         {ticket (may be empty)}
  end;

  { --- Certificate (RFC 5246, 7.4.2) --- }

  {One certificate of the chain: DER bytes (ASN.1Cert).}
  TTLSCertificateEntry = record
    Data: TBytes;
  end;
  TTLSCertificateEntries = array of TTLSCertificateEntry;

  {Parsed Certificate message (body): chain from leaf to root.}
  TTLSCertificateMessage = record
    Certificates: TTLSCertificateEntries;
  end;

  { --- ServerKeyExchange (RFC 5246, 7.4.3; RFC 4492, 5.4) --- }

  {Key exchange algorithm used in ServerKeyExchange.}
  TTLSKeyExchangeAlgorithm = (keaUnknown, keaECDHE, keaDHE);

  {Parsed ServerKeyExchange message.
    For ECDHE, CurveType/NamedCurve/ECDHEPublicKey are filled; for DHE —
    DHPrime/DHGenerator/DHPublic. Common fields — SignatureAlgorithm and
    Signature; SignedParams stores the parameters (ServerECDHParams or
    ServerDHParams) signed by the server together with
    client_random||server_random (see TLS12ServerKeyExchangeSignedData).}
  TTLSServerKeyExchange = record
    Algorithm: TTLSKeyExchangeAlgorithm;
    CurveType: Byte;                   { 3 = named_curve }
    NamedCurve: TTLSNamedGroup;
    ECDHEPublicKey: TBytes;            {point on curve}
    DHPrime: TBytes;                   { dh_p }
    DHGenerator: TBytes;               { dh_g }
    DHPublic: TBytes;                  { dh_Ys }
    SignatureAlgorithm: TTLSSignatureScheme;
    Signature: TBytes;
    SignedParams: TBytes;              {parameter bytes under signature}
  end;

  { --- ClientKeyExchange (RFC 5246, 7.4.7; RFC 4492, 5.7) --- }

  {Client ephemeral key pair for ECDHE (RFC 4492, 5.4/5.7).
    NIST P-256 (secp256r1) and P-384 (secp384r1) are supported.
    The public point is encoded in SEC 1 uncompressed (0x04 || X || Y),
    and in ClientKeyExchange — as ECPoint opaque<1..2^8-1>.}
  TTLS12ECDHEClientKey = class
  private
    FNamedGroup: TTLSNamedGroup;
    FCurve: TECCurve;
    FKeyPair: TECKeypair;
  public
    constructor Create(ANamedGroup: TTLSNamedGroup);
    destructor Destroy; override;
    {Whether the group is supported (secp256r1 / secp384r1).}
    class function IsSupportedGroup(ANamedGroup: TTLSNamedGroup): Boolean;
    {Size of curve coordinate/field in bytes (32 for P-256, 48 for P-384).}
    class function FieldSize(ANamedGroup: TTLSNamedGroup): Integer;
    {Client public point (SEC 1, uncompressed).}
    function PublicPoint: TBytes;
    {ClientKeyExchange body: ECPoint(1) || 0x04 || X || Y.}
    function ClientKeyExchangeBody: TBytes;
    {Premaster secret = X-coordinate of the shared point, padded with leading
      zeros to the field size (RFC 4492, 5.10). Error if the server point
      does not lie on the curve or is the point at infinity.}
    function PremasterSecret(const AServerPublicPoint: TBytes): TBytes;
    property NamedGroup: TTLSNamedGroup read FNamedGroup;
    property Curve: TECCurve read FCurve;
    property KeyPair: TECKeypair read FKeyPair;
  end;

  {Client ephemeral key for DHE (RFC 5246, 7.4.7.1/8.1.2).
    Initialized with server parameters (p, g) and generates Yc.}
  TTLS12DHEClientKey = class
  private
    FKey: TDHKey;
    FPrimeLen: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    {Sets server p and g and generates the private key and Yc.}
    procedure InitFromServerParams(const APrime, AGenerator: TBytes);
    {Public value Yc, padded with leading zeros to the length of p.}
    function PublicKey: TBytes;
    {ClientKeyExchange body: DH_Yc(2) || Yc.}
    function ClientKeyExchangeBody: TBytes;
    {Premaster secret = Ys^priv mod p with leading zero
      bytes stripped (RFC 5246, 8.1.2; compatible with OpenSSL DH_compute_key).}
    function PremasterSecret(const AServerPublic: TBytes): TBytes;
    property Key: TDHKey read FKey;
  end;

  {Parsed certificate chain from the TLS Certificate message
    (RFC 5246, 7.4.2). Stores certificates from leaf (index 0) to root and
    owns them (frees in the destructor).}
  TTLS12CertChain = class
  private
    FCerts: array of TX509Cert;
    function GetCount: LongInt;
    function GetLeaf: TX509Cert;
  public
    constructor Create;
    destructor Destroy; override;
    {Parses DER certificates from the Certificate message. Invalid DER
      → ETLS12Error. An empty message yields an empty chain (Count = 0).}
    procedure Parse(const ACertificates: TTLSCertificateMessage);
    property Count: LongInt read GetCount;
    {Server certificate (first in the chain); nil for an empty chain.}
    property Leaf: TX509Cert read GetLeaf;
    {Certificate by index (0 = leaf). Error if the index is out of range.}
    function Cert(AIndex: LongInt): TX509Cert;
    {Validates the chain against the trusted store ATrustStore:
      the leaf must be signed by a trusted CA (possibly via
      intermediate certificates from the chain itself). Validity periods are checked against
      ANow (0 = current time).}
    function Verify(const ATrustStore: TCertStore; AHops: LongInt = 8;
      ANow: TDateTime = 0): TVerifyResult;
  end;

  {Handshake message assembly buffer: accepts record fragments
    (a handshake message may be split across several records and,
    conversely, several messages may reside in one record),
    extracts one complete message at a time and accumulates the transcript
    (raw bytes of all extracted messages) for computing Finished.}
  TTLSHandshakeBuffer = class
  private
    FData: TBytes;        {not yet parsed bytes}
    FTranscript: TBytes;  {raw bytes of all extracted messages}
  public
    procedure Clear;
    {Appends bytes (a handshake record fragment).}
    procedure Append(const AData: TBytes); overload;
    procedure Append(const ABuffer; ACount: Integer); overload;
    {How many unparsed bytes remain.}
    function PendingBytes: Integer;
    {Full length of the next message (header+body) or -1 if
      the header has not been received yet.}
    function PeekMessageLength: Integer;
    {Whether the buffer contains at least one complete message.}
    function HasCompleteMessage: Boolean;
    {Extracts one complete message; False — no complete message.}
    function TryTakeMessage(out AMsg: TTLSHandshakeMessage): Boolean;
    {Extracts one complete message; error if none.}
    function TakeMessage: TTLSHandshakeMessage;
    {Transcript: header||body of all extracted messages.}
    property Transcript: TBytes read FTranscript;
    function TranscriptLength: Integer;
    {Appends an outgoing handshake message to the transcript (ClientHello,
      ClientKeyExchange, client Finished): the Finished hash must account for
      all handshake messages, including sent ones.}
    procedure AppendTranscript(AType: TTLSHandshakeType;
      const ABody: TBytes); overload;
    procedure AppendTranscript(const AMsg: TTLSHandshakeMessage); overload;
  end;

  {Alert (RFC 5246, 7.2): notification of a connection problem.}
  TTLSAlertLevel = (alWarning = TLSAlertLevelWarning,
    alFatal = TLSAlertLevelFatal);

  TTLSAlertDescription = (
    adCloseNotify = 0,
    adUnexpectedMessage = 10,
    adBadRecordMac = 20,
    adDecryptionFailed = 21,
    adRecordOverflow = 22,
    adDecompressionFailure = 30,
    adHandshakeFailure = 40,
    adNoCertificate = 41,
    adBadCertificate = 42,
    adUnsupportedCertificate = 43,
    adCertificateRevoked = 44,
    adCertificateExpired = 45,
    adCertificateUnknown = 46,
    adIllegalParameter = 47,
    adUnknownCa = 48,
    adAccessDenied = 49,
    adDecodeError = 50,
    adDecryptError = 51,
    adExportRestriction = 60,
    adProtocolVersion = 70,
    adInsufficientSecurity = 71,
    adInternalError = 80,
    adUserCanceled = 90,
    adNoRenegotiation = 100,
    adUnsupportedExtension = 110);

  {Parsed Alert message: level(1) || description(1).}
  TTLSAlert = record
    Level: TTLSAlertLevel;
    Description: TTLSAlertDescription;
  end;

  ETLS12Error = class(Exception);

  {Byte transport abstraction for the TLS client: TCP socket,
    TMemoryStream (tests) or mock.

      Read  > 0 — that many bytes read;
      Read  = 0 — normal stream closure (EOF);
      Read  < 0 — error/timeout (TLSTransportError).
      Write > 0 — that many bytes written (may be less than requested,
                  the caller must repeat until fully sent);
      Write < 0 — error.

    The implementation operates within a single connection and a single thread.}
  ITLSTransport = interface
    ['{C1D2E3F4-A5B6-47C8-9D0E-1F2A3B4C5D6E}']
    function Read(var ABuffer; ACount: LongInt): LongInt;
    function Write(const ABuffer; ACount: LongInt): LongInt;
    function BytesAvailable: LongInt;
  end;

  {ITLSTransport adapter over a regular TStream (used in tests
    and as a basis for the socket transport). Ownership of the stream remains
    with the caller: the object merely uses it.}
  TTLSStreamTransport = class(TInterfacedObject, ITLSTransport)
  private
    FStream: TStream;
  public
    constructor Create(AStream: TStream);
    function Read(var ABuffer; ACount: LongInt): LongInt;
    function Write(const ABuffer; ACount: LongInt): LongInt;
    function BytesAvailable: LongInt;
    property Stream: TStream read FStream;
  end;
  {High-level TLS 1.2 client (RFC 5246): performs the full handshake over
    ITLSTransport and provides Send/Recv for application data.

    The client is single-use: one Connect() per instance. After the
    handshake completes, Send/Recv operate on the encrypted channel.

    Certificate verification: if TrustStore is set (non-nil), the server
    certificate chain is verified against it during Connect. If TrustStore
    is nil, no chain verification is performed (the chain is still parsed
    and available via CertChain).

    Only ephemeral key exchange (ECDHE/DHE) with AEAD cipher suites is
    supported. CBC and static-RSA suites are rejected with ETLS12Error. }
  TTLS12Client = class
  private
    FTransport: ITLSTransport;
    FOptions: TTLSClientHelloOptions;
    FBuffer: TTLSHandshakeBuffer;
    FChain: TTLS12CertChain;
    FTrustStore: TCertStore;
    FConnected: Boolean;
    FHandshakeDone: Boolean;
    FCipherSuite: TTLSCipherSuite;
    FAEADMode: TTLSAEADMode;
    FHashKind: THashKind;
    FClientWriteKey: TBytes;
    FServerWriteKey: TBytes;
    FClientWriteIV: TBytes;
    FServerWriteIV: TBytes;
    FClientSeq: QWord;
    FServerSeq: QWord;
    FMasterSecret: TBytes;
    FRecvBuf: TBytes;
    FRecvPos: Integer;
    function GetHandshakeDone: Boolean;
    function GetCipherSuite: TTLSCipherSuite;
    function GetPendingBytes: LongInt;
    procedure DoHandshake;
  public
    constructor Create;
    destructor Destroy; override;
    {Configuration (set before Connect).}
    property Options: TTLSClientHelloOptions read FOptions write FOptions;
    {Optional trust store for certificate verification (not owned by client).
      If nil, no chain verification is performed.}
    property TrustStore: TCertStore read FTrustStore write FTrustStore;
    {Performs the TLS 1.2 handshake over ATransport.
      Raises ETLS12Error on any protocol or verification error.}
    procedure Connect(ATransport: ITLSTransport);
    {Sends application data over the encrypted channel.
      Must be called after a successful Connect.}
    procedure Send(const AData: TBytes);
    {Receives application data. Returns the number of bytes read:
      > 0 — bytes read into ABuffer;
      = 0 — connection closed by peer (close_notify or EOF);
      < 0 — error (TLSTransportError).
      Must be called after a successful Connect.}
    function Recv(var ABuffer; ACount: LongInt): LongInt;
    {Sends close_notify alert and closes the connection.}
    procedure Shutdown;
    {Closes the connection without sending close_notify.}
    procedure Close;
    {Whether the handshake has completed.}
    property HandshakeDone: Boolean read GetHandshakeDone;
    {Negotiated cipher suite (valid after Connect).}
    property CipherSuite: TTLSCipherSuite read GetCipherSuite;
    {Server certificate chain (owned by the client; freed in Destroy).
      nil if the server did not send a Certificate message.}
    function CertChain: TTLS12CertChain;
    {Number of decrypted application-data bytes still buffered inside the
      client (analogous to SSL_pending / OpenSSL's BytesAvailable).}
    property PendingBytes: LongInt read GetPendingBytes;
  end;

{--- Record layer: type conversion and header ------------------- }

{Content type -> byte on the wire and back.}
function TLSContentTypeToByte(AType: TTLSContentType): Byte;
function ByteToTLSContentType(AValue: Byte): TTLSContentType;
{Check that the byte is a known TLS 1.2 content type.}
function IsKnownContentType(AValue: Byte): Boolean;

{Record version 0x0303 (TLS 1.2).}
function IsTLS12Version(AVersion: Word): Boolean;

{Assembles the 5-byte record header (big-endian). AMaxLength sets
  the allowed maximum fragment length (2^14 for plaintext,
  2^14+2048 for ciphertext).}
function EncodeTLSRecordHeader(AContentType: TTLSContentType;
  AVersion: Word; ALength: Integer;
  AMaxLength: Integer = TLSRecordMaxPayload): TBytes;

{Parses the 5-byte record header.}
function DecodeTLSRecordHeader(const AHeader: TBytes): TTLSRecordHeader;

{--- Record layer: assembly and parsing of a whole record -----------------------}

{Assembles a single TLS record from a fragment. AMaxLength sets the
  allowed fragment limit: 2^14 for plaintext records (RFC 5246,
  6.2.1) and 2^14+2048 for ciphertext records (RFC 5246, 6.2.3).}
function EncodeTLSRecord(AContentType: TTLSContentType;
  const AFragment: TBytes; AVersion: Word = TLS12Version;
  AMaxLength: Integer = TLSRecordMaxPayload): TBytes;

{Parses a single record from the buffer (header + fragment).}
function DecodeTLSRecord(const AData: TBytes): TTLSRecord;

{--- Record layer: exchange over transport ------------------------------}

{Reads exactly ACount bytes, handling partial reads; on EOF or
  transport error raises ETLS12Error.}
procedure TLSReadAll(ATransport: ITLSTransport; var ABuffer; ACount: Integer);

{Writes exactly ACount bytes, repeating partial writes; on transport
  error raises ETLS12Error.}
procedure TLSWriteAll(ATransport: ITLSTransport; const ABuffer; ACount: Integer);

{Reads a single complete record from the transport (header + fragment).
  Fragment length is limited by TLSRecordMaxCiphertext.}
function ReadTLSRecord(ATransport: ITLSTransport): TTLSRecord;

{Assembles and sends a single record. AMaxLength sets the allowed
  fragment limit (2^14 for plaintext, 2^14+2048 for ciphertext).}
procedure WriteTLSRecord(ATransport: ITLSTransport;
  AContentType: TTLSContentType; const AFragment: TBytes;
  AVersion: Word = TLS12Version;
  AMaxLength: Integer = TLSRecordMaxPayload);

{Sends data, splitting it into records no longer than 2^14 bytes
  (RFC 5246, 6.2.1). An empty buffer produces an empty record.}
procedure WriteTLSFragmented(ATransport: ITLSTransport;
  AContentType: TTLSContentType; const AData: TBytes;
  AVersion: Word = TLS12Version);

{--- AEAD record protection (RFC 5288 / RFC 7905) ----------------------}

{Key length (write_key) for AEAD mode.}
function TLSAEADKeyLength(AMode: TTLSAEADMode): Integer;

{Length of fixed_iv (write_IV) extracted from the key block: 4 bytes for
  AES-GCM, 12 bytes for ChaCha20-Poly1305.}
function TLSAEADFixedIvLength(AMode: TTLSAEADMode): Integer;

{Length of the explicit nonce at the start of the record fragment: 8 bytes for AES-GCM,
  0 for ChaCha20-Poly1305.}
function TLSAEADExplicitNonceLength(AMode: TTLSAEADMode): Integer;

{Additional data (AAD) of a TLS 1.2 AEAD record:
    seq_num(8) || type(1) || version(2) || plaintext_length(2).}
function TLSAEADAdditionalData(ASeqNum: QWord; AContentType: TTLSContentType;
  AVersion: Word; APlainLength: Integer): TBytes;

{12-byte AEAD nonce:
    AES-GCM            — fixed_iv(4) || explicit_nonce(8);
    ChaCha20-Poly1305  — fixed_iv(12) xor (0x00000000 || seq_num(8)).}
function TLSAEADNonce(AMode: TTLSAEADMode; const AFixedIv,
  AExplicitNonce: TBytes; ASeqNum: QWord): TBytes;

{Encrypts the plaintext and assembles the record fragment:
    AES-GCM            — explicit_nonce(8) || ciphertext || tag(16);
    ChaCha20-Poly1305  — ciphertext || tag(16).}
function TLSAEADEncryptFragment(AMode: TTLSAEADMode; const AKey, AFixedIv,
  AExplicitNonce: TBytes; ASeqNum: QWord; AContentType: TTLSContentType;
  AVersion: Word; const APlain: TBytes): TBytes; overload;

{Same, but the explicit nonce for AES-GCM is generated by CSPRNG.}
function TLSAEADEncryptFragment(AMode: TTLSAEADMode; const AKey, AFixedIv:
  TBytes; ASeqNum: QWord; AContentType: TTLSContentType; AVersion: Word;
  const APlain: TBytes): TBytes; overload;

{Parses and decrypts an AEAD record fragment. False — corrupted
  fragment or invalid tag (plaintext is not output in this case).}
function TLSAEADDecryptFragment(AMode: TTLSAEADMode; const AKey, AFixedIv:
  TBytes; ASeqNum: QWord; AContentType: TTLSContentType; AVersion: Word;
  const AFragment: TBytes; out APlain: TBytes): Boolean;

{--- Handshake: type conversion and header -------------------- }

{Handshake message type -> wire byte and back.}
function TLSHandshakeTypeToByte(AType: TTLSHandshakeType): Byte;
function ByteToTLSHandshakeType(AValue: Byte): TTLSHandshakeType;
{Check that a byte is a known handshake message type.}
function IsKnownHandshakeType(AValue: Byte): Boolean;
{Human-readable type name (for diagnostics/logs).}
function TLSHandshakeTypeName(AType: TTLSHandshakeType): string;

{Builds the 4-byte handshake message header.}
function EncodeTLSHandshakeHeader(AType: TTLSHandshakeType;
  ABodyLength: Integer): TBytes;

{Parses the 4-byte handshake message header.}
function DecodeTLSHandshakeHeader(const AData: TBytes): TTLSHandshakeHeader;

{--- Handshake: building and parsing a single message -------------------- }

{Builds a handshake message: header + body.}
function EncodeTLSHandshakeMessage(AType: TTLSHandshakeType;
  const ABody: TBytes): TBytes;

{Parses one complete handshake message (header + body); extra
  bytes after the body are ignored. If the buffer is shorter than the declared length —
  error ETLS12Error. }
function DecodeTLSHandshakeMessage(const AData: TBytes): TTLSHandshakeMessage;

{Same, but returns the number of bytes used (4 + body length) —
  for sequential parsing of several messages from one buffer. }
function DecodeTLSHandshakeMessage(const AData: TBytes;
  out AConsumed: Integer): TTLSHandshakeMessage; overload;

{--- Handshake: flights --------------------------------------------- }

{Builds a flight (sequence of messages) into a single byte stream.}
function EncodeTLSHandshakeFlight(
  const AMessages: TTLSHandshakeMessages): TBytes;

{Sends one handshake message in one or more records.}
procedure WriteTLSHandshakeMessage(ATransport: ITLSTransport;
  AType: TTLSHandshakeType; const ABody: TBytes;
  AVersion: Word = TLS12Version);

{Sends a flight, splitting the byte stream into records no longer than 2^14
  (RFC 5246, 6.2.3). An empty flight sends nothing. }
procedure WriteTLSHandshakeFlight(ATransport: ITLSTransport;
  const AMessages: TTLSHandshakeMessages; AVersion: Word = TLS12Version);

{Reads handshake messages from the transport, assembling them into ABuffer until
  it extracts a message whose type is in ATerminators (it also
  goes into AMessages). Returns False if the transport closed
  before a terminating message was encountered.

  If ATerminators is empty, reads records until the first extracted
  message, then takes all other already complete messages from ABuffer and
  returns True (without waiting for a terminating message). }
function ReadTLSHandshakeFlight(ATransport: ITLSTransport;
  ABuffer: TTLSHandshakeBuffer; const ATerminators: TTLSHandshakeTypeSet;
  out AMessages: TTLSHandshakeMessages): Boolean;

{Reads one handshake message of any type.}
function ReadTLSHandshakeMessage(ATransport: ITLSTransport;
  ABuffer: TTLSHandshakeBuffer): TTLSHandshakeMessage;

{Searches the set for a message of the given type.}
function FindTLSHandshakeMessage(const AMessages: TTLSHandshakeMessages;
  AType: TTLSHandshakeType; out AMsg: TTLSHandshakeMessage): Boolean;
  {--- ClientHello: building (RFC 5246, 7.4.1.2) ------------------------ }

{Human-readable cipher suite name (for diagnostics/logs).}
function TLSCipherSuiteName(ASuite: TTLSCipherSuite): string;

{Default values: ECDHE priority, then DHE (AEAD only). }
function TLS12DefaultCipherSuites: TTLSCipherSuites;

{Whether the cipher suite is supported by this implementation. Only
  suites from TLS12DefaultCipherSuites are supported: ephemeral key exchange (ECDHE/DHE)
  and AEAD encryption (AES-GCM/ChaCha20-Poly1305). CBC suites and static-RSA
  (including TLS_RSA_WITH_* / TLS_ECDHE_*_CBC_*) are intentionally NOT supported. }
function TLS12CipherSuiteSupported(ASuite: TTLSCipherSuite): Boolean;

{' AEAD record-layer mode for a supported suite. Unsupported
  suite (incl. CBC/static-RSA) → ETLS12Error. '}
function TLS12CipherSuiteAEADMode(ASuite: TTLSCipherSuite): TTLSAEADMode;

{' Explicitly checks that the suite is supported: otherwise ETLS12Error with a clear
  message, separately noting unsupported CBC/static-RSA suites. '}
procedure TLS12CheckCipherSuiteSupported(ASuite: TTLSCipherSuite);
function TLS12DefaultSupportedGroups: TTLSNamedGroups;
function TLS12DefaultSignatureAlgorithms: TTLSSignatureSchemes;

{' Default options: EMS and renegotiation_info enabled, SCSV — not. '}
function DefaultTLS12ClientHelloOptions: TTLSClientHelloOptions;

{' Options with given SNI and client random. '}
function BuildTLS12ClientHelloOptions(const AServerName: string;
  const AClientRandom: TBytes): TTLSClientHelloOptions;

{' --- ClientHello: individual extensions ------------------------------ '}

{ server_name (SNI, RFC 6066): HostName, name_type = host_name. }
function EncodeTLSServerNameExtension(const AHostName: string): TTLSExtension;

{ supported_groups / elliptic_curves (RFC 4492/7919). }
function EncodeTLSSupportedGroupsExtension(
  const AGroups: TTLSNamedGroups): TTLSExtension;

{ signature_algorithms (RFC 5246, 7.4.1.4.1). }
function EncodeTLSSignatureAlgorithmsExtension(
  const ASchemes: TTLSSignatureSchemes): TTLSExtension;

{' extended_master_secret (RFC 7627, empty extension). '}
function EncodeTLSExtendedMasterSecretExtension: TTLSExtension;

{ renegotiation_info (RFC 5746). AData — renegotiated_connection (0..255). }
function EncodeTLSRenegotiationInfoExtension(const AData: TBytes): TTLSExtension;

{' --- ClientHello: extension list --------------------------------- '}

{' Builds the extensions block: total_length(2) || (type||len||data)*. '}
function EncodeTLSExtensions(const AExtensions: TTLSExtensions): TBytes;

{' Parses the extensions block (including the 2-byte length prefix). '}
function DecodeTLSExtensions(const AData: TBytes): TTLSExtensions;

{' Searches for an extension by type. '}
function FindTLSExtension(const AExtensions: TTLSExtensions;
  AExtType: Word; out AExt: TTLSExtension): Boolean;

{' --- ClientHello: message assembly and parsing ------------------------- '}

{' Builds the ClientHello body from options (version, random, session_id,
  cipher_suites, compression_methods, extensions). '}
function BuildTLS12ClientHelloBody(
  const AOptions: TTLSClientHelloOptions): TBytes;

{' Builds the full ClientHello handshake message. '}
function BuildTLS12ClientHello(
  const AOptions: TTLSClientHelloOptions): TBytes;

{' Parses the ClientHello body and extracts SNI/groups/sig_algs/EMS/RI. '}
function ParseTLS12ClientHello(const AData: TBytes): TTLSClientHello;

{' Sends ClientHello to the transport in one or more records. '}
procedure WriteTLS12ClientHello(ATransport: ITLSTransport;
  const AOptions: TTLSClientHelloOptions);


{' --- ServerHello/Certificate/ServerKeyExchange: parsing ------------- '}

{' Parses the ServerHello body: version, random, session_id, cipher_suite,
  compression_method, extensions and derived fields (EMS, RI, SNI-ack,
  session_ticket). '}
function ParseTLS12ServerHello(const AData: TBytes): TTLSServerHello;

{' Parses the Certificate body: list of certificates from leaf to root. '}
function ParseTLS12Certificate(const AData: TBytes): TTLSCertificateMessage;

{' Parses the ServerKeyExchange body with auto-detection of ECDHE/DHE by
  the first byte (3 = named_curve -> ECDHE, otherwise DHE). '}
function ParseTLS12ServerKeyExchange(const AData: TBytes): TTLSServerKeyExchange;

{' Parses the ServerKeyExchange body with an explicitly specified algorithm. '}
function ParseTLS12ServerKeyExchange(const AData: TBytes;
  AAlgorithm: TTLSKeyExchangeAlgorithm): TTLSServerKeyExchange; overload;

{Checks that the ServerHelloDone body is empty (RFC 5246, 7.4.5);
  throws ETLS12Error if the body is non-empty.}
procedure CheckTLS12ServerHelloDone(const AData: TBytes);

{Data that the server signed in ServerKeyExchange:
  client_random || server_random || SignedParams.}
function TLS12ServerKeyExchangeSignedData(const AClientRandom,
  AServerRandom: TBytes; const ASKE: TTLSServerKeyExchange): TBytes;

{Parses the server flight: finds ServerHello/Certificate/
  ServerKeyExchange/ServerHelloDone among AMessages. Certificate and SKE
  are optional (static RSA does not send SKE); AHasCertificates and
  AHasKeyExchange report whether they were present. False — no ServerHello or
  ServerHelloDone.}
function ParseTLS12ServerFlight(const AMessages: TTLSHandshakeMessages;
  out AHello: TTLSServerHello; out ACertificates: TTLSCertificateMessage;
  out AKeyExchange: TTLSServerKeyExchange;
  out AHasCertificates, AHasKeyExchange: Boolean): Boolean;


{ --- ClientKeyExchange: build/parse (RFC 5246, 7.4.7; RFC 4492, 5.7) - }

{Builds the ClientKeyExchange body with the client's public point:
  ECPoint opaque<1..2^8-1> (RFC 4492, 5.7).}
function BuildTLS12ECDHEClientKeyExchangeBody(const APublicPoint: TBytes): TBytes;

{Builds the ClientKeyExchange body with DH_Yc: opaque<1..2^16-1>
  (RFC 5246, 7.4.7.1).}
function BuildTLS12DHEClientKeyExchangeBody(const AYc: TBytes): TBytes;

{Parses the ClientKeyExchange body, returning the client's public key
  (point for ECDHE or Yc for DHE). False — invalid length/empty
  body; APublicKey is nil in that case.}
function ParseTLS12ClientKeyExchange(const AData: TBytes;
  AAlgorithm: TTLSKeyExchangeAlgorithm; out APublicKey: TBytes): Boolean;

{ --- Server flight verification (RFC 5246, 7.4.3; RFC 5280) -------- }

{Whether the signature scheme is supported for verification (RSA PKCS#1 v1.5
  SHA-256/384/512, ECDSA P-256/P-384/P-521).}
function TLS12SignatureSchemeSupported(AScheme: TTLSSignatureScheme): Boolean;

{ X.509 signature algorithm OID corresponding to the TLS scheme; '' — scheme not
  supported. For RSA sets the verification hash (VerifyDataSignature). }
function TLS12SignatureSchemeX509OID(AScheme: TTLSSignatureScheme): string;

{Signature scheme key algorithm: 1 — RSA, 3 — ECDSA (low byte of the scheme,
  RFC 5246, 7.4.1.4.1); 0 — unknown. }
function TLS12SignatureSchemeKeyAlgorithm(AScheme: TTLSSignatureScheme): Byte;

{Human-readable signature scheme name (for diagnostics/logs). }
function TLS12SignatureSchemeName(AScheme: TTLSSignatureScheme): string;

{Verifies the signature of arbitrary data with the certificate's public key
  ACert using TLS scheme AScheme. False — empty data/signature, key type
  does not match the scheme, or the signature is invalid.}
function VerifyTLS12Signature(const ACert: TX509Cert;
  const AData, ASignature: TBytes; AScheme: TTLSSignatureScheme): Boolean;

{Verifies the ServerKeyExchange signature: signed data is
  client_random || server_random || SignedParams (RFC 5246, 7.4.3).
  False — empty signature, key type mismatch, or invalid signature.
  Unsupported signature scheme → ETLS12Error.}
function VerifyTLS12ServerKeyExchange(const ALeafCert: TX509Cert;
  const AClientRandom, AServerRandom: TBytes;
  const ASKE: TTLSServerKeyExchange): Boolean;

{Same, but the certificate is taken from the parsed chain (chain.Leaf). }
function VerifyTLS12ServerKeyExchange(const AChain: TTLS12CertChain;
  const AClientRandom, AServerRandom: TBytes;
  const ASKE: TTLSServerKeyExchange): Boolean; overload;

{Parses the certificate chain from the Certificate message into a new
  TTLS12CertChain (owns the memory; the caller must Free).}
function ParseTLS12CertChain(
  const ACertificates: TTLSCertificateMessage): TTLS12CertChain;

{ --- ChangeCipherSpec (RFC 5246, 7.1) -------------------------------- }

{ChangeCipherSpec body: a single byte 0x01. }
function EncodeTLSChangeCipherSpec: TBytes;

{Checks that the ChangeCipherSpec body is exactly one byte 0x01. }
procedure CheckTLSChangeCipherSpec(const ACipherSpec: TBytes);

{Sends a ChangeCipherSpec record. }
procedure WriteTLS12ChangeCipherSpec(ATransport: ITLSTransport;
  AVersion: Word = TLS12Version);

{Reads a ChangeCipherSpec record and checks its contents. }
procedure ReadTLS12ChangeCipherSpec(ATransport: ITLSTransport);

{ --- Finished / VerifyData (RFC 5246, 7.4.9) ------------------------- }

{PRF hash bound to cipher suite: SHA-384 for *-SHA384 suites,
  SHA-256 for other supported ones; unknown suite → ETLS12Error.}
function TLS12CipherSuiteHashKind(ASuite: TTLSCipherSuite): THashKind;

{Hash(handshake_messages) — hash of the handshake transcript.}
function TLS12TranscriptHash(AKind: THashKind;
  const ATranscript: TBytes): TBytes;

{verify_data = PRF(master_secret, ALabel, Hash(transcript))[0..11]
  (always 12 bytes in TLS 1.2). ALabel is TLSFinishedLabelClient or
  TLSFinishedLabelServer.}
function TLS12VerifyData(AKind: THashKind; const AMasterSecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;

{Constant-time comparison of verify_data with the expected value.}
function TLS12VerifyFinished(AKind: THashKind; const AMasterSecret: TBytes;
  const ALabel: AnsiString; const ATranscript,
  AVerifyData: TBytes): Boolean;

{Finished body: verify_data(12) without header.}
function EncodeTLS12FinishedBody(const AVerifyData: TBytes): TBytes;

{Full Finished handshake message: header || verify_data.}
function BuildTLS12Finished(const AVerifyData: TBytes): TBytes;

{Parses the Finished body, returning verify_data (exactly 12 bytes).}
function ParseTLS12FinishedBody(const ABody: TBytes): TBytes;

{Builds the Finished handshake message for the specified role.}
function TLS12FinishedMessage(AKind: THashKind;
  const AMasterSecret: TBytes; const ALabel: AnsiString;
  const ATranscript: TBytes): TBytes;

{Verifies the received Finished body against the transcript.}
function TLS12CheckFinished(AKind: THashKind;
  const AMasterSecret: TBytes; const ALabel: AnsiString;
  const ATranscript, ABody: TBytes): Boolean;

{ --- Alert (RFC 5246, 7.2) ------------------------------------------- }

function TLSAlertLevelToByte(ALevel: TTLSAlertLevel): Byte;
function ByteToTLSAlertLevel(AValue: Byte): TTLSAlertLevel;
function TLSAlertDescriptionToByte(ADescription: TTLSAlertDescription): Byte;
function ByteToTLSAlertDescription(AValue: Byte): TTLSAlertDescription;
function IsKnownAlertDescription(AValue: Byte): Boolean;
function TLSAlertLevelName(ALevel: TTLSAlertLevel): string;
function TLSAlertDescriptionName(ADescription: TTLSAlertDescription): string;

{Builds the Alert body: level(1) || description(1).}
function EncodeTLSAlert(ALevel: TTLSAlertLevel;
  ADescription: TTLSAlertDescription): TBytes;

{Parses the Alert body (exactly 2 bytes).}
function DecodeTLSAlert(const AData: TBytes): TTLSAlert;

{Sends an Alert record.}
procedure WriteTLS12Alert(ATransport: ITLSTransport; ALevel: TTLSAlertLevel;
  ADescription: TTLSAlertDescription; AVersion: Word = TLS12Version);

{Reads an Alert record (record type must be ctAlert) and parses it.}
function ReadTLS12Alert(ATransport: ITLSTransport): TTLSAlert;

{Whether the alert is fatal (level 2).}
function TLS12AlertIsFatal(const AAlert: TTLSAlert): Boolean;




implementation

uses
  tls.aes, tls.chacha20, tls.rand, tls.prf;

function TLSContentTypeToByte(AType: TTLSContentType): Byte;
begin
  Result := Byte(Ord(AType));
end;

function ByteToTLSContentType(AValue: Byte): TTLSContentType;
begin
  case AValue of
    Ord(ctChangeCipherSpec): Result := ctChangeCipherSpec;
    Ord(ctAlert): Result := ctAlert;
    Ord(ctHandshake): Result := ctHandshake;
    Ord(ctApplicationData): Result := ctApplicationData;
  else
    raise ETLS12Error.CreateFmt(
      'TLS record: unknown content type %d', [AValue]);
  end;
end;

function IsKnownContentType(AValue: Byte): Boolean;
begin
  Result := (AValue = Ord(ctChangeCipherSpec)) or (AValue = Ord(ctAlert)) or
    (AValue = Ord(ctHandshake)) or (AValue = Ord(ctApplicationData));
end;

function IsTLS12Version(AVersion: Word): Boolean;
begin
  Result := AVersion = TLS12Version;
end;

{--- Record header ---------------------------------------------------- }

function EncodeTLSRecordHeader(AContentType: TTLSContentType;
  AVersion: Word; ALength: Integer; AMaxLength: Integer): TBytes;
begin
  if ALength < 0 then
    raise ETLS12Error.CreateFmt(
      'TLS record: negative fragment length %d', [ALength]);
  if ALength > AMaxLength then
    raise ETLS12Error.CreateFmt(
      'TLS record: fragment length %d exceeds limit %d',
      [ALength, AMaxLength]);
  Result := nil;
  SetLength(Result, TLSRecordHeaderLen);
  Result[0] := TLSContentTypeToByte(AContentType);
  Result[1] := Byte((AVersion shr 8) and $FF);
  Result[2] := Byte(AVersion and $FF);
  Result[3] := Byte((ALength shr 8) and $FF);
  Result[4] := Byte(ALength and $FF);
end;

function DecodeTLSRecordHeader(const AHeader: TBytes): TTLSRecordHeader;
begin
  if Length(AHeader) < TLSRecordHeaderLen then
    raise ETLS12Error.CreateFmt(
      'TLS record: header shorter than %d bytes', [TLSRecordHeaderLen]);
  Result.ContentType := ByteToTLSContentType(AHeader[0]);
  Result.Version := (Word(AHeader[1]) shl 8) or Word(AHeader[2]);
  Result.Length := (Word(AHeader[3]) shl 8) or Word(AHeader[4]);
end;

{--- Whole record ----------------------------------------------------- }

function EncodeTLSRecord(AContentType: TTLSContentType;
  const AFragment: TBytes; AVersion: Word;
  AMaxLength: Integer): TBytes;
var
  Len: Integer;
begin
  Len := Length(AFragment);
  if Len > AMaxLength then
    raise ETLS12Error.CreateFmt(
      'TLS record: fragment %d bytes exceeds limit (%d)',
      [Len, AMaxLength]);
  Result := nil;
  SetLength(Result, TLSRecordHeaderLen + Len);
  Result[0] := TLSContentTypeToByte(AContentType);
  Result[1] := Byte((AVersion shr 8) and $FF);
  Result[2] := Byte(AVersion and $FF);
  Result[3] := Byte((Len shr 8) and $FF);
  Result[4] := Byte(Len and $FF);
  if Len > 0 then
    Move(AFragment[0], Result[TLSRecordHeaderLen], Len);
end;

function DecodeTLSRecord(const AData: TBytes): TTLSRecord;
var
  Header: TTLSRecordHeader;
begin
  Header := DecodeTLSRecordHeader(AData);
  if Header.Length > TLSRecordMaxCiphertext then
    raise ETLS12Error.CreateFmt(
      'TLS record: fragment length %d exceeds limit %d',
      [Header.Length, TLSRecordMaxCiphertext]);
  if Length(AData) < TLSRecordHeaderLen + Integer(Header.Length) then
    raise ETLS12Error.CreateFmt(
      'TLS record: buffer %d bytes shorter than header+fragment (%d)',
      [Length(AData), TLSRecordHeaderLen + Integer(Header.Length)]);
  Result.ContentType := Header.ContentType;
  Result.Version := Header.Version;
  SetLength(Result.Fragment, Header.Length);
  if Header.Length > 0 then
    Move(AData[TLSRecordHeaderLen], Result.Fragment[0], Header.Length);
end;

{ --- Transport exchange ------------------------------------------- }

procedure TLSReadAll(ATransport: ITLSTransport; var ABuffer; ACount: Integer);
var
  P: PByte;
  Got, N: LongInt;
begin
  if ACount < 0 then
    raise ETLS12Error.CreateFmt(
      'TLS transport: negative read length %d', [ACount]);
  if ACount = 0 then
    Exit;
  P := @ABuffer;
  Got := 0;
  while Got < ACount do
  begin
    N := ATransport.Read(P[Got], ACount - Got);
    if N = TLSTransportEOF then
      raise ETLS12Error.CreateFmt(
        'TLS record: unexpected end of stream (received %d of %d bytes)',
        [Got, ACount]);
    if N < 0 then
      raise ETLS12Error.Create('TLS record: transport read error');
    Inc(Got, N);
  end;
end;

procedure TLSWriteAll(ATransport: ITLSTransport; const ABuffer; ACount: Integer);
var
  P: PByte;
  Sent, N: LongInt;
begin
  if ACount < 0 then
    raise ETLS12Error.CreateFmt(
      'TLS transport: negative write length %d', [ACount]);
  if ACount = 0 then
    Exit;
  P := @ABuffer;
  Sent := 0;
  while Sent < ACount do
  begin
    N := ATransport.Write(P[Sent], ACount - Sent);
    if N <= 0 then
      raise ETLS12Error.Create('TLS record: transport write error');
    Inc(Sent, N);
  end;
end;

function ReadTLSRecord(ATransport: ITLSTransport): TTLSRecord;
var
  Raw: TBytes;
  Header: TTLSRecordHeader;
begin
  SetLength(Raw, TLSRecordHeaderLen);
  TLSReadAll(ATransport, Raw[0], TLSRecordHeaderLen);
  Header := DecodeTLSRecordHeader(Raw);
  if Header.Length > TLSRecordMaxCiphertext then
    raise ETLS12Error.CreateFmt(
      'TLS record: fragment length %d exceeds limit %d',
      [Header.Length, TLSRecordMaxCiphertext]);
  Result.ContentType := Header.ContentType;
  Result.Version := Header.Version;
  SetLength(Result.Fragment, Header.Length);
  if Header.Length > 0 then
    TLSReadAll(ATransport, Result.Fragment[0], Header.Length);
end;

procedure WriteTLSRecord(ATransport: ITLSTransport;
  AContentType: TTLSContentType; const AFragment: TBytes;
  AVersion: Word; AMaxLength: Integer);
var
  Rec: TBytes;
begin
  Rec := EncodeTLSRecord(AContentType, AFragment, AVersion, AMaxLength);
  TLSWriteAll(ATransport, Rec[0], Length(Rec));
end;

procedure WriteTLSFragmented(ATransport: ITLSTransport;
  AContentType: TTLSContentType; const AData: TBytes;
  AVersion: Word);
var
  Offset, Total, Chunk: Integer;
  Part: TBytes;
begin
  Total := Length(AData);
  if Total = 0 then
  begin
    WriteTLSRecord(ATransport, AContentType, nil, AVersion);
    Exit;
  end;
  Offset := 0;
  while Offset < Total do
  begin
    Chunk := Total - Offset;
    if Chunk > TLSRecordMaxPayload then
      Chunk := TLSRecordMaxPayload;
    SetLength(Part, Chunk);
    Move(AData[Offset], Part[0], Chunk);
    WriteTLSRecord(ATransport, AContentType, Part, AVersion);
    Inc(Offset, Chunk);
  end;
end;

{ --- AEAD record protection --------------------------------------------- }

function TLSAEADKeyLength(AMode: TTLSAEADMode): Integer;
begin
  case AMode of
    aeadAES128GCM: Result := 16;
    aeadAES256GCM: Result := 32;
    aeadChaCha20Poly1305: Result := 32;
  else
    raise ETLS12Error.Create('TLS AEAD: unknown mode');
  end;
end;

function TLSAEADFixedIvLength(AMode: TTLSAEADMode): Integer;
begin
  case AMode of
    aeadAES128GCM, aeadAES256GCM: Result := TLSGCMFixedIvLen;
    aeadChaCha20Poly1305: Result := TLSChaCha20FixedIvLen;
  else
    raise ETLS12Error.Create('TLS AEAD: unknown mode');
  end;
end;

function TLSAEADExplicitNonceLength(AMode: TTLSAEADMode): Integer;
begin
  case AMode of
    aeadAES128GCM, aeadAES256GCM: Result := TLSGCMExplicitNonceLen;
    aeadChaCha20Poly1305: Result := 0;
  else
    raise ETLS12Error.Create('TLS AEAD: unknown mode');
  end;
end;

function TLSAEADAdditionalData(ASeqNum: QWord; AContentType: TTLSContentType;
  AVersion: Word; APlainLength: Integer): TBytes;
var
  i: Integer;
begin
  if (APlainLength < 0) or (APlainLength > TLSRecordMaxPayload) then
    raise ETLS12Error.CreateFmt(
      'TLS AEAD: invalid plaintext length %d', [APlainLength]);
  SetLength(Result, 13);
  { seq_num: 8 bytes big-endian. }
  for i := 0 to 7 do
    Result[7 - i] := Byte(ASeqNum shr (8 * i));
  Result[8] := TLSContentTypeToByte(AContentType);
  Result[9] := Byte((AVersion shr 8) and $FF);
  Result[10] := Byte(AVersion and $FF);
  Result[11] := Byte((APlainLength shr 8) and $FF);
  Result[12] := Byte(APlainLength and $FF);
end;

function TLSAEADNonce(AMode: TTLSAEADMode; const AFixedIv,
  AExplicitNonce: TBytes; ASeqNum: QWord): TBytes;
var
  i: Integer;
begin
  case AMode of
    aeadAES128GCM, aeadAES256GCM:
      begin
        if Length(AFixedIv) <> TLSGCMFixedIvLen then
          raise ETLS12Error.Create('TLS AES-GCM: fixed_iv not 4 bytes');
        if Length(AExplicitNonce) <> TLSGCMExplicitNonceLen then
          raise ETLS12Error.Create('TLS AES-GCM: explicit nonce not 8 bytes');
        SetLength(Result, 12);
        Move(AFixedIv[0], Result[0], TLSGCMFixedIvLen);
        Move(AExplicitNonce[0], Result[TLSGCMFixedIvLen],
          TLSGCMExplicitNonceLen);
      end;
    aeadChaCha20Poly1305:
      begin
        if Length(AFixedIv) <> TLSChaCha20FixedIvLen then
          raise ETLS12Error.Create('TLS ChaCha20: fixed_iv not 12 bytes');
        SetLength(Result, 12);
        Move(AFixedIv[0], Result[0], TLSChaCha20FixedIvLen);
        { XOR of low 8 bytes with seq_num (big-endian). }
        for i := 0 to 7 do
          Result[4 + i] := Result[4 + i] xor Byte(ASeqNum shr (8 * (7 - i)));
      end;
  else
    raise ETLS12Error.Create('TLS AEAD: unknown mode');
  end;
end;

function TLSAEADEncryptFragment(AMode: TTLSAEADMode; const AKey, AFixedIv,
  AExplicitNonce: TBytes; ASeqNum: QWord; AContentType: TTLSContentType;
  AVersion: Word; const APlain: TBytes): TBytes;
var
  Nonce, AAD, Cipher, Tag: TBytes;
begin
  if Length(APlain) > TLSRecordMaxPayload then
    raise ETLS12Error.CreateFmt(
      'TLS AEAD: plaintext %d bytes exceeds limit 2^14 (%d)',
      [Length(APlain), TLSRecordMaxPayload]);
  AAD := TLSAEADAdditionalData(ASeqNum, AContentType, AVersion,
    Length(APlain));
  Nonce := TLSAEADNonce(AMode, AFixedIv, AExplicitNonce, ASeqNum);
  case AMode of
    aeadAES128GCM, aeadAES256GCM:
      begin
        if Length(AKey) <> TLSAEADKeyLength(AMode) then
          raise ETLS12Error.CreateFmt(
            'TLS AES-GCM: key %d bytes (expected %d)',
            [Length(AKey), TLSAEADKeyLength(AMode)]);
        AESGCMEncrypt(AKey, Nonce, AAD, APlain, Cipher, Tag);
        SetLength(Result, TLSGCMExplicitNonceLen + Length(Cipher) +
          TLSAEADTagLen);
        Move(AExplicitNonce[0], Result[0], TLSGCMExplicitNonceLen);
        if Length(Cipher) > 0 then
          Move(Cipher[0], Result[TLSGCMExplicitNonceLen], Length(Cipher));
        Move(Tag[0], Result[TLSGCMExplicitNonceLen + Length(Cipher)],
          TLSAEADTagLen);
      end;
    aeadChaCha20Poly1305:
      begin
        if Length(AKey) <> 32 then
          raise ETLS12Error.CreateFmt(
            'TLS ChaCha20: key %d bytes (expected 32)', [Length(AKey)]);
        ChaCha20Poly1305Encrypt(AKey, Nonce, AAD, APlain, Cipher, Tag);
        SetLength(Result, Length(Cipher) + TLSAEADTagLen);
        if Length(Cipher) > 0 then
          Move(Cipher[0], Result[0], Length(Cipher));
        Move(Tag[0], Result[Length(Cipher)], TLSAEADTagLen);
      end;
  else
    raise ETLS12Error.Create('TLS AEAD: unknown mode');
  end;
end;

function TLSAEADEncryptFragment(AMode: TTLSAEADMode; const AKey, AFixedIv:
  TBytes; ASeqNum: QWord; AContentType: TTLSContentType; AVersion: Word;
  const APlain: TBytes): TBytes;
var
  Explicit: TBytes;
begin
  if TLSAEADExplicitNonceLength(AMode) > 0 then
    RandomBytes(Explicit, TLSAEADExplicitNonceLength(AMode))
  else
    Explicit := nil;
  Result := TLSAEADEncryptFragment(AMode, AKey, AFixedIv, Explicit, ASeqNum,
    AContentType, AVersion, APlain);
end;

function TLSAEADDecryptFragment(AMode: TTLSAEADMode; const AKey, AFixedIv:
  TBytes; ASeqNum: QWord; AContentType: TTLSContentType; AVersion: Word;
  const AFragment: TBytes; out APlain: TBytes): Boolean;
var
  Explicit, Cipher, Tag, Nonce, AAD: TBytes;
  ExplLen, TagLen, CtLen: Integer;
begin
  APlain := nil;
  ExplLen := TLSAEADExplicitNonceLength(AMode);
  TagLen := TLSAEADTagLen;
  if Length(AFragment) < ExplLen + TagLen then
    Exit(False);
  CtLen := Length(AFragment) - ExplLen - TagLen;
  if CtLen > TLSRecordMaxPayload then
    Exit(False);
  if ExplLen > 0 then
    Explicit := Copy(AFragment, 0, ExplLen)
  else
    Explicit := nil;
  Cipher := Copy(AFragment, ExplLen, CtLen);
  Tag := Copy(AFragment, ExplLen + CtLen, TagLen);
  AAD := TLSAEADAdditionalData(ASeqNum, AContentType, AVersion, CtLen);
  Nonce := TLSAEADNonce(AMode, AFixedIv, Explicit, ASeqNum);
  case AMode of
    aeadAES128GCM, aeadAES256GCM:
      begin
        if Length(AKey) <> TLSAEADKeyLength(AMode) then
          Exit(False);
        Result := AESGCMDecrypt(AKey, Nonce, AAD, Cipher, Tag, APlain);
      end;
    aeadChaCha20Poly1305:
      begin
        if Length(AKey) <> 32 then
          Exit(False);
        Result := ChaCha20Poly1305Decrypt(AKey, Nonce, AAD, Cipher, Tag,
          APlain);
      end;
  else
    Result := False;
  end;
end;

{ --- Handshake: types and header ------------------------------------ }

function TLSHandshakeTypeToByte(AType: TTLSHandshakeType): Byte;
begin
  Result := Byte(Ord(AType));
end;

function IsKnownHandshakeType(AValue: Byte): Boolean;
begin
  case AValue of
    Ord(htHelloRequest), Ord(htClientHello), Ord(htServerHello),
    Ord(htNewSessionTicket), Ord(htEndOfEarlyData), Ord(htEncryptedExtensions),
    Ord(htCertificate), Ord(htServerKeyExchange), Ord(htCertificateRequest),
    Ord(htServerHelloDone), Ord(htCertificateVerify),
    Ord(htClientKeyExchange), Ord(htFinished), Ord(htCertificateStatus),
    Ord(htSupplementalData), Ord(htKeyUpdate), Ord(htMessageHash):
      Result := True;
  else
    Result := False;
  end;
end;

function ByteToTLSHandshakeType(AValue: Byte): TTLSHandshakeType;
begin
  if not IsKnownHandshakeType(AValue) then
    raise ETLS12Error.CreateFmt(
      'TLS handshake: unknown message type %d', [AValue]);
  Result := TTLSHandshakeType(AValue);
end;

function TLSHandshakeTypeName(AType: TTLSHandshakeType): string;
begin
  case AType of
    htHelloRequest: Result := 'hello_request';
    htClientHello: Result := 'client_hello';
    htServerHello: Result := 'server_hello';
    htNewSessionTicket: Result := 'new_session_ticket';
    htEndOfEarlyData: Result := 'end_of_early_data';
    htEncryptedExtensions: Result := 'encrypted_extensions';
    htCertificate: Result := 'certificate';
    htServerKeyExchange: Result := 'server_key_exchange';
    htCertificateRequest: Result := 'certificate_request';
    htServerHelloDone: Result := 'server_hello_done';
    htCertificateVerify: Result := 'certificate_verify';
    htClientKeyExchange: Result := 'client_key_exchange';
    htFinished: Result := 'finished';
    htCertificateStatus: Result := 'certificate_status';
    htSupplementalData: Result := 'supplemental_data';
    htKeyUpdate: Result := 'key_update';
    htMessageHash: Result := 'message_hash';
  else
    Result := Format('unknown(%d)', [Ord(AType)]);
  end;
end;

function EncodeTLSHandshakeHeader(AType: TTLSHandshakeType;
  ABodyLength: Integer): TBytes;
begin
  if (ABodyLength < 0) or (ABodyLength > TLSHandshakeMaxLength) then
    raise ETLS12Error.CreateFmt(
      'TLS handshake: invalid body length %d', [ABodyLength]);
  SetLength(Result, TLSHandshakeHeaderLen);
  Result[0] := TLSHandshakeTypeToByte(AType);
  Result[1] := Byte((ABodyLength shr 16) and $FF);
  Result[2] := Byte((ABodyLength shr 8) and $FF);
  Result[3] := Byte(ABodyLength and $FF);
end;

function DecodeTLSHandshakeHeader(const AData: TBytes): TTLSHandshakeHeader;
begin
  if Length(AData) < TLSHandshakeHeaderLen then
    raise ETLS12Error.CreateFmt(
      'TLS handshake: header shorter than %d bytes', [TLSHandshakeHeaderLen]);
  Result.MsgType := ByteToTLSHandshakeType(AData[0]);
  Result.Length := (Integer(AData[1]) shl 16) or
    (Integer(AData[2]) shl 8) or Integer(AData[3]);
end;

{ --- Handshake: single message --------------------------------------- }

function EncodeTLSHandshakeMessage(AType: TTLSHandshakeType;
  const ABody: TBytes): TBytes;
var
  Hdr: TBytes;
  BodyLen: Integer;
begin
  BodyLen := Length(ABody);
  Hdr := EncodeTLSHandshakeHeader(AType, BodyLen);
  SetLength(Result, TLSHandshakeHeaderLen + BodyLen);
  Move(Hdr[0], Result[0], TLSHandshakeHeaderLen);
  if BodyLen > 0 then
    Move(ABody[0], Result[TLSHandshakeHeaderLen], BodyLen);
end;

function DecodeTLSHandshakeMessage(const AData: TBytes): TTLSHandshakeMessage;
var
  Hdr: TTLSHandshakeHeader;
begin
  Hdr := DecodeTLSHandshakeHeader(AData);
  if Length(AData) < TLSHandshakeHeaderLen + Hdr.Length then
    raise ETLS12Error.CreateFmt(
      'TLS handshake: buffer %d bytes shorter than message (%d)',
      [Length(AData), TLSHandshakeHeaderLen + Hdr.Length]);
  Result.MsgType := Hdr.MsgType;
  SetLength(Result.Body, Hdr.Length);
  if Hdr.Length > 0 then
    Move(AData[TLSHandshakeHeaderLen], Result.Body[0], Hdr.Length);
end;

function DecodeTLSHandshakeMessage(const AData: TBytes;
  out AConsumed: Integer): TTLSHandshakeMessage;
begin
  Result := DecodeTLSHandshakeMessage(AData);
  AConsumed := TLSHandshakeHeaderLen + Length(Result.Body);
end;

{ --- Handshake: assembly buffer ----------------------------------------- }

procedure TTLSHandshakeBuffer.Clear;
begin
  FData := nil;
  FTranscript := nil;
end;

procedure TTLSHandshakeBuffer.Append(const AData: TBytes);
begin
  if Length(AData) > 0 then
    Append(AData[0], Length(AData));
end;

procedure TTLSHandshakeBuffer.Append(const ABuffer; ACount: Integer);
var
  N: Integer;
begin
  if ACount < 0 then
    raise ETLS12Error.CreateFmt(
      'TLS handshake: negative fragment length %d', [ACount]);
  if ACount = 0 then
    Exit;
  N := Length(FData);
  SetLength(FData, N + ACount);
  Move(ABuffer, FData[N], ACount);
end;

function TTLSHandshakeBuffer.PendingBytes: Integer;
begin
  Result := Length(FData);
end;

function TTLSHandshakeBuffer.PeekMessageLength: Integer;
var
  Hdr: TTLSHandshakeHeader;
begin
  if Length(FData) < TLSHandshakeHeaderLen then
    Exit(-1);
  Hdr := DecodeTLSHandshakeHeader(FData);
  Result := TLSHandshakeHeaderLen + Hdr.Length;
end;

function TTLSHandshakeBuffer.HasCompleteMessage: Boolean;
var
  Total: Integer;
begin
  Total := PeekMessageLength;
  Result := (Total >= 0) and (Length(FData) >= Total);
end;

function TTLSHandshakeBuffer.TryTakeMessage(
  out AMsg: TTLSHandshakeMessage): Boolean;
var
  Hdr: TTLSHandshakeHeader;
  Total, Rest: Integer;
  Raw: TBytes;
begin
  Result := False;
  if Length(FData) < TLSHandshakeHeaderLen then
    Exit;
  Hdr := DecodeTLSHandshakeHeader(FData);
  Total := TLSHandshakeHeaderLen + Hdr.Length;
  if Length(FData) < Total then
    Exit;
  AMsg.MsgType := Hdr.MsgType;
  SetLength(AMsg.Body, Hdr.Length);
  if Hdr.Length > 0 then
    Move(FData[TLSHandshakeHeaderLen], AMsg.Body[0], Hdr.Length);
  { Transcript: raw bytes (header + body) in order of appearance. }
  Raw := Copy(FData, 0, Total);
  Rest := Length(FTranscript);
  SetLength(FTranscript, Rest + Total);
  Move(Raw[0], FTranscript[Rest], Total);
  { Remove the parsed message from the buffer. }
  Rest := Length(FData) - Total;
  if Rest > 0 then
    FData := Copy(FData, Total, Rest)
  else
    FData := nil;
  Result := True;
end;

function TTLSHandshakeBuffer.TakeMessage: TTLSHandshakeMessage;
begin
  if not TryTakeMessage(Result) then
    raise ETLS12Error.Create('TLS handshake: no complete message');
end;

function TTLSHandshakeBuffer.TranscriptLength: Integer;
begin
  Result := Length(FTranscript);
end;

procedure TTLSHandshakeBuffer.AppendTranscript(AType: TTLSHandshakeType;
  const ABody: TBytes);
var
  Raw: TBytes;
  Rest: Integer;
begin
  Raw := EncodeTLSHandshakeMessage(AType, ABody);
  Rest := Length(FTranscript);
  SetLength(FTranscript, Rest + Length(Raw));
  if Length(Raw) > 0 then
    Move(Raw[0], FTranscript[Rest], Length(Raw));
end;

procedure TTLSHandshakeBuffer.AppendTranscript(
  const AMsg: TTLSHandshakeMessage);
begin
  AppendTranscript(AMsg.MsgType, AMsg.Body);
end;

{ --- Handshake: flights ----------------------------------------------- }

function EncodeTLSHandshakeFlight(
  const AMessages: TTLSHandshakeMessages): TBytes;
var
  i, Total, Offset: Integer;
  MsgBytes: TBytes;
begin
  Total := 0;
  for i := 0 to High(AMessages) do
    Inc(Total, TLSHandshakeHeaderLen + Length(AMessages[i].Body));
  SetLength(Result, Total);
  Offset := 0;
  for i := 0 to High(AMessages) do
  begin
    MsgBytes := EncodeTLSHandshakeMessage(AMessages[i].MsgType,
      AMessages[i].Body);
    Move(MsgBytes[0], Result[Offset], Length(MsgBytes));
    Inc(Offset, Length(MsgBytes));
  end;
end;

procedure WriteTLSHandshakeMessage(ATransport: ITLSTransport;
  AType: TTLSHandshakeType; const ABody: TBytes; AVersion: Word);
var
  Bytes: TBytes;
begin
  Bytes := EncodeTLSHandshakeMessage(AType, ABody);
  WriteTLSFragmented(ATransport, ctHandshake, Bytes, AVersion);
end;

procedure WriteTLSHandshakeFlight(ATransport: ITLSTransport;
  const AMessages: TTLSHandshakeMessages; AVersion: Word);
var
  Bytes: TBytes;
begin
  if Length(AMessages) = 0 then
    Exit;
  Bytes := EncodeTLSHandshakeFlight(AMessages);
  WriteTLSFragmented(ATransport, ctHandshake, Bytes, AVersion);
end;

function ReadTLSHandshakeFlight(ATransport: ITLSTransport;
  ABuffer: TTLSHandshakeBuffer; const ATerminators: TTLSHandshakeTypeSet;
  out AMessages: TTLSHandshakeMessages): Boolean;
var
  Msg: TTLSHandshakeMessage;
  Rec: TTLSRecord;
  TerminatorMode: Boolean;
begin
  AMessages := nil;
  TerminatorMode := ATerminators <> [];
  while True do
  begin
    while ABuffer.TryTakeMessage(Msg) do
    begin
      SetLength(AMessages, Length(AMessages) + 1);
      AMessages[High(AMessages)] := Msg;
      if TerminatorMode and (Msg.MsgType in ATerminators) then
        Exit(True);
    end;
    if (not TerminatorMode) and (Length(AMessages) > 0) then
      Exit(True);
    Rec := ReadTLSRecord(ATransport);
    if Rec.ContentType <> ctHandshake then
      raise ETLS12Error.CreateFmt(
        'TLS handshake: expected handshake record, got type %d',
        [Ord(Rec.ContentType)]);
    ABuffer.Append(Rec.Fragment);
  end;
end;

function ReadTLSHandshakeMessage(ATransport: ITLSTransport;
  ABuffer: TTLSHandshakeBuffer): TTLSHandshakeMessage;
var
  Rec: TTLSRecord;
begin
  repeat
    if ABuffer.TryTakeMessage(Result) then
      Exit;
    Rec := ReadTLSRecord(ATransport);
    if Rec.ContentType <> ctHandshake then
      raise ETLS12Error.CreateFmt(
        'TLS handshake: expected handshake record, got type %d',
        [Ord(Rec.ContentType)]);
    ABuffer.Append(Rec.Fragment);
  until False;
end;

function FindTLSHandshakeMessage(const AMessages: TTLSHandshakeMessages;
  AType: TTLSHandshakeType; out AMsg: TTLSHandshakeMessage): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(AMessages) do
    if AMessages[i].MsgType = AType then
    begin
      AMsg := AMessages[i];
      Exit(True);
    end;
  Result := False;
end;

{ --- ClientHello: helper encoders ------------------------ }

{ Concatenation of byte strings. }
function TLSBufBytes(const A, B: TBytes): TBytes;
var
  LA, LB: Integer;
begin
  LA := Length(A);
  LB := Length(B);
  SetLength(Result, LA + LB);
  if LA > 0 then
    Move(A[0], Result[0], LA);
  if LB > 0 then
    Move(B[0], Result[LA], LB);
end;

{ Append one byte. }
function TLSBufByte(const A: TBytes; B: Byte): TBytes;
var
  LA: Integer;
begin
  LA := Length(A);
  SetLength(Result, LA + 1);
  if LA > 0 then
    Move(A[0], Result[0], LA);
  Result[LA] := B;
end;

{ Append 2 bytes big-endian. }
function TLSBufWord(const A: TBytes; W: Word): TBytes;
begin
  Result := TLSBufByte(A, Byte((W shr 8) and $FF));
  Result := TLSBufByte(Result, Byte(W and $FF));
end;

{ Read 2 bytes big-endian (bounds checked by caller). }
function TLSReadWordAt(const AData: TBytes; AOffset: Integer): Word;
begin
  Result := (Word(AData[AOffset]) shl 8) or Word(AData[AOffset + 1]);
end;

{ Read 3 bytes big-endian (bounds checked by caller). }
function TLSReadTripleAt(const AData: TBytes; AOffset: Integer): LongWord;
begin
  Result := (LongWord(AData[AOffset]) shl 16) or
            (LongWord(AData[AOffset + 1]) shl 8) or
            LongWord(AData[AOffset + 2]);
end;

{ Read 4 bytes big-endian (bounds checked by caller). }
function TLSReadDWordAt(const AData: TBytes; AOffset: Integer): LongWord;
begin
  Result := (LongWord(AData[AOffset]) shl 24) or
            (LongWord(AData[AOffset + 1]) shl 16) or
            (LongWord(AData[AOffset + 2]) shl 8) or
            LongWord(AData[AOffset + 3]);
end;

{ String -> bytes without changing encoding (for SNI/ASCII). }
function TLSStringToBytes(const S: string): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Byte(S[i]);
end;

{ --- ClientHello: default values ------------------------------ }

function TLSCipherSuiteName(ASuite: TTLSCipherSuite): string;
begin
  case ASuite of
    TLSCipherEmptyRenegotiationInfoSCSV:
      Result := 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV';
    TLSCipherFallbackSCSV: Result := 'TLS_FALLBACK_SCSV';
    TLSCipherRSA_AES128GCM_SHA256: Result := 'TLS_RSA_WITH_AES_128_GCM_SHA256';
    TLSCipherRSA_AES256GCM_SHA384: Result := 'TLS_RSA_WITH_AES_256_GCM_SHA384';
    TLSCipherDHE_RSA_AES128GCM_SHA256:
      Result := 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256';
    TLSCipherDHE_RSA_AES256GCM_SHA384:
      Result := 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384';
    TLSCipherECDHE_ECDSA_AES128GCM_SHA256:
      Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256';
    TLSCipherECDHE_ECDSA_AES256GCM_SHA384:
      Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
    TLSCipherECDHE_RSA_AES128GCM_SHA256:
      Result := 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
    TLSCipherECDHE_RSA_AES256GCM_SHA384:
      Result := 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384';
    TLSCipherECDHE_RSA_CHACHA20POLY1305_SHA256:
      Result := 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256';
    TLSCipherECDHE_ECDSA_CHACHA20POLY1305_SHA256:
      Result := 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256';
    { CBC / static-RSA: known by name, but not supported. }
    TLSCipherRSA_RC4_128_SHA: Result := 'TLS_RSA_WITH_RC4_128_SHA';
    TLSCipherRSA_3DES_EDE_CBC_SHA: Result := 'TLS_RSA_WITH_3DES_EDE_CBC_SHA';
    TLSCipherRSA_AES128CBC_SHA: Result := 'TLS_RSA_WITH_AES_128_CBC_SHA';
    TLSCipherRSA_AES256CBC_SHA: Result := 'TLS_RSA_WITH_AES_256_CBC_SHA';
    TLSCipherRSA_AES128CBC_SHA256: Result := 'TLS_RSA_WITH_AES_128_CBC_SHA256';
    TLSCipherRSA_AES256CBC_SHA256: Result := 'TLS_RSA_WITH_AES_256_CBC_SHA256';
    TLSCipherDHE_RSA_AES128CBC_SHA: Result := 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA';
    TLSCipherDHE_RSA_AES256CBC_SHA: Result := 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA';
    TLSCipherECDHE_RSA_AES128CBC_SHA:
      Result := 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA';
    TLSCipherECDHE_RSA_AES256CBC_SHA:
      Result := 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA';
    TLSCipherECDHE_ECDSA_AES128CBC_SHA:
      Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA';
    TLSCipherECDHE_ECDSA_AES256CBC_SHA:
      Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA';
  else
    Result := Format('0x%.4X', [ASuite]);
  end;
end;

function TLS12DefaultCipherSuites: TTLSCipherSuites;
const
  Suites: array[0..7] of Word = (
    TLSCipherECDHE_ECDSA_AES128GCM_SHA256,
    TLSCipherECDHE_ECDSA_AES256GCM_SHA384,
    TLSCipherECDHE_RSA_AES128GCM_SHA256,
    TLSCipherECDHE_RSA_AES256GCM_SHA384,
    TLSCipherECDHE_ECDSA_CHACHA20POLY1305_SHA256,
    TLSCipherECDHE_RSA_CHACHA20POLY1305_SHA256,
    TLSCipherDHE_RSA_AES128GCM_SHA256,
    TLSCipherDHE_RSA_AES256GCM_SHA384);
var
  i: Integer;
begin
  SetLength(Result, Length(Suites));
  for i := 0 to High(Suites) do
    Result[i] := Suites[i];
end;

{ The set of supported suites matches the default list:
  ephemeral key exchange (ECDHE/DHE) + AEAD (AES-GCM/ChaCha20-Poly1305).
  static-RSA (key transport) and block CBC suites are not implemented. }
function TLS12CipherSuiteSupported(ASuite: TTLSCipherSuite): Boolean;
begin
  case ASuite of
    TLSCipherECDHE_ECDSA_AES128GCM_SHA256,
    TLSCipherECDHE_ECDSA_AES256GCM_SHA384,
    TLSCipherECDHE_RSA_AES128GCM_SHA256,
    TLSCipherECDHE_RSA_AES256GCM_SHA384,
    TLSCipherECDHE_ECDSA_CHACHA20POLY1305_SHA256,
    TLSCipherECDHE_RSA_CHACHA20POLY1305_SHA256,
    TLSCipherDHE_RSA_AES128GCM_SHA256,
    TLSCipherDHE_RSA_AES256GCM_SHA384:
      Result := True;
  else
    Result := False;
  end;
end;

function TLS12CipherSuiteAEADMode(ASuite: TTLSCipherSuite): TTLSAEADMode;
begin
  case ASuite of
    TLSCipherECDHE_ECDSA_AES128GCM_SHA256,
    TLSCipherECDHE_RSA_AES128GCM_SHA256,
    TLSCipherDHE_RSA_AES128GCM_SHA256:
      Result := aeadAES128GCM;
    TLSCipherECDHE_ECDSA_AES256GCM_SHA384,
    TLSCipherECDHE_RSA_AES256GCM_SHA384,
    TLSCipherDHE_RSA_AES256GCM_SHA384:
      Result := aeadAES256GCM;
    TLSCipherECDHE_ECDSA_CHACHA20POLY1305_SHA256,
    TLSCipherECDHE_RSA_CHACHA20POLY1305_SHA256:
      Result := aeadChaCha20Poly1305;
  else
    raise ETLS12Error.CreateFmt(
      'TLS 1.2: cipher suite 0x%.4X (%s) is not supported by the record layer: ' +
      'only AEAD AES-GCM/ChaCha20-Poly1305 are available',
      [ASuite, TLSCipherSuiteName(ASuite)]);
  end;
end;

procedure TLS12CheckCipherSuiteSupported(ASuite: TTLSCipherSuite);
begin
  if not TLS12CipherSuiteSupported(ASuite) then
    raise ETLS12Error.CreateFmt(
      'TLS 1.2: cipher suite 0x%.4X (%s) is not supported: implemented ' +
      'only ephemeral key exchange (ECDHE/DHE) with AEAD ' +
      '(AES-GCM/ChaCha20-Poly1305); CBC and static-RSA (key transport) ' +
      'are deliberately excluded', [ASuite, TLSCipherSuiteName(ASuite)]);
end;

{ Groups advertised in the ClientHello MUST be groups the client can
  actually complete, otherwise a server that prefers an unimplemented
  group (typically X25519) picks it and the handshake dies with
  'TLS ECDHE: unsupported group 0x001D'. ECDHE is implemented only for
  P-256/P-384 (see TTLS12ECDHEClientKey.IsSupportedGroup); the FFDHE
  groups are fine because DHE reads the explicit dh_p/dh_g sent in
  ServerKeyExchange and does not depend on the advertised group. }
function TLS12DefaultSupportedGroups: TTLSNamedGroups;
const
  Groups: array[0..4] of Word = (
    TLSNamedGroupSecp256r1, TLSNamedGroupSecp384r1,
    TLSNamedGroupFFDHE2048, TLSNamedGroupFFDHE3072,
    TLSNamedGroupFFDHE4096);
var
  i: Integer;
begin
  SetLength(Result, Length(Groups));
  for i := 0 to High(Groups) do
    Result[i] := Groups[i];
end;

{ By default, only schemes that our verifier can verify
  (RSA PKCS#1 v1.5 and ECDSA); rsa_pss/ed25519 are deliberately not enabled. }
function TLS12DefaultSignatureAlgorithms: TTLSSignatureSchemes;
const
  Schemes: array[0..5] of Word = (
    TLSSigECDSA_Secp256r1_SHA256, TLSSigECDSA_Secp384r1_SHA384,
    TLSSigECDSA_Secp521r1_SHA512, TLSSigRSA_PKCS1_SHA256,
    TLSSigRSA_PKCS1_SHA384, TLSSigRSA_PKCS1_SHA512);
var
  i: Integer;
begin
  SetLength(Result, Length(Schemes));
  for i := 0 to High(Schemes) do
    Result[i] := Schemes[i];
end;

function DefaultTLS12ClientHelloOptions: TTLSClientHelloOptions;
begin
  Result.ServerName := '';
  Result.SessionID := nil;
  Result.ClientRandom := nil;
  Result.CipherSuites := nil;
  Result.SupportedGroups := nil;
  Result.SignatureAlgorithms := nil;
  Result.ExtendedMasterSecret := True;
  Result.RenegotiationInfo := True;
  Result.RenegotiationInfoData := nil;
  Result.EmptyRenegotiationInfoSCSV := False;
  Result.FallbackSCSV := False;
end;

function BuildTLS12ClientHelloOptions(const AServerName: string;
  const AClientRandom: TBytes): TTLSClientHelloOptions;
begin
  Result := DefaultTLS12ClientHelloOptions;
  Result.ServerName := AServerName;
  Result.ClientRandom := AClientRandom;
end;

{' --- ClientHello: individual extensions ------------------------------ '}

function EncodeTLSServerNameExtension(const AHostName: string): TTLSExtension;
var
  Host, Entry, Data: TBytes;
begin
  if AHostName = '' then
    raise ETLS12Error.Create('TLS SNI: empty server name');
  Host := TLSStringToBytes(AHostName);
  if Length(Host) > $FFFF then
    raise ETLS12Error.Create('TLS SNI: server name longer than 65535 bytes');
  Entry := TLSBufByte(nil, TLSServerNameTypeHostName);
  Entry := TLSBufWord(Entry, Length(Host));
  Entry := TLSBufBytes(Entry, Host);
  Data := TLSBufWord(nil, Length(Entry));
  Data := TLSBufBytes(Data, Entry);
  Result.ExtType := TLSExtServerName;
  Result.Data := Data;
end;

function EncodeTLSSupportedGroupsExtension(
  const AGroups: TTLSNamedGroups): TTLSExtension;
var
  Body, Data: TBytes;
  i: Integer;
begin
  if Length(AGroups) = 0 then
    raise ETLS12Error.Create('TLS supported_groups: empty group list');
  Body := nil;
  for i := 0 to High(AGroups) do
    Body := TLSBufWord(Body, AGroups[i]);
  Data := TLSBufWord(nil, Length(Body));
  Data := TLSBufBytes(Data, Body);
  Result.ExtType := TLSExtSupportedGroups;
  Result.Data := Data;
end;

function EncodeTLSSignatureAlgorithmsExtension(
  const ASchemes: TTLSSignatureSchemes): TTLSExtension;
var
  Body, Data: TBytes;
  i: Integer;
begin
  if Length(ASchemes) = 0 then
    raise ETLS12Error.Create('TLS signature_algorithms: empty list');
  Body := nil;
  for i := 0 to High(ASchemes) do
    Body := TLSBufWord(Body, ASchemes[i]);
  Data := TLSBufWord(nil, Length(Body));
  Data := TLSBufBytes(Data, Body);
  Result.ExtType := TLSExtSignatureAlgorithms;
  Result.Data := Data;
end;

function EncodeTLSExtendedMasterSecretExtension: TTLSExtension;
begin
  Result.ExtType := TLSExtExtendedMasterSecret;
  Result.Data := nil;
end;

function EncodeTLSRenegotiationInfoExtension(
  const AData: TBytes): TTLSExtension;
var
  Data: TBytes;
begin
  if Length(AData) > 255 then
    raise ETLS12Error.Create('TLS renegotiation_info: data longer than 255 bytes');
  Data := TLSBufByte(nil, Length(AData));
  Data := TLSBufBytes(Data, AData);
  Result.ExtType := TLSExtRenegotiationInfo;
  Result.Data := Data;
end;

function EncodeTLSExtensions(const AExtensions: TTLSExtensions): TBytes;
var
  Body: TBytes;
  i: Integer;
begin
  Body := nil;
  for i := 0 to High(AExtensions) do
  begin
    if Length(AExtensions[i].Data) > $FFFF then
      raise ETLS12Error.Create('TLS extension: data longer than 65535 bytes');
    Body := TLSBufWord(Body, AExtensions[i].ExtType);
    Body := TLSBufWord(Body, Length(AExtensions[i].Data));
    Body := TLSBufBytes(Body, AExtensions[i].Data);
  end;
  if Length(Body) > $FFFF then
    raise ETLS12Error.Create('TLS extensions: total length greater than 65535');
  Result := TLSBufWord(nil, Length(Body));
  Result := TLSBufBytes(Result, Body);
end;

function DecodeTLSExtensions(const AData: TBytes): TTLSExtensions;
var
  Pos, Total, ExtLen, n: Integer;
  ExtType: Word;
begin
  Result := nil;
  if Length(AData) = 0 then
    Exit;
  if Length(AData) < 2 then
    raise ETLS12Error.Create('TLS extensions: buffer shorter than 2 bytes');
  Total := Integer(TLSReadWordAt(AData, 0));
  if Total <> Length(AData) - 2 then
    raise ETLS12Error.CreateFmt(
      'TLS extensions: declared %d bytes, available %d',
      [Total, Length(AData) - 2]);
  Pos := 2;
  n := 0;
  while Pos < Length(AData) do
  begin
    if Pos + 4 > Length(AData) then
      raise ETLS12Error.Create('TLS extensions: truncated header');
    ExtType := TLSReadWordAt(AData, Pos);
    ExtLen := Integer(TLSReadWordAt(AData, Pos + 2));
    Inc(Pos, 4);
    if Pos + ExtLen > Length(AData) then
      raise ETLS12Error.Create('TLS extensions: truncated data');
    SetLength(Result, n + 1);
    Result[n].ExtType := ExtType;
    Result[n].Data := Copy(AData, Pos, ExtLen);
    Inc(Pos, ExtLen);
    Inc(n);
  end;
end;

function FindTLSExtension(const AExtensions: TTLSExtensions;
  AExtType: Word; out AExt: TTLSExtension): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(AExtensions) do
    if AExtensions[i].ExtType = AExtType then
    begin
      AExt := AExtensions[i];
      Exit(True);
    end;
  Result := False;
end;

{ --- ClientHello: building body and message ---------------------------- }

function BuildTLS12ClientHelloExtensions(
  const AOptions: TTLSClientHelloOptions): TTLSExtensions;
var
  n: Integer;
  Groups: TTLSNamedGroups;
  Sigs: TTLSSignatureSchemes;
begin
  Result := nil;
  n := 0;
  if AOptions.ServerName <> '' then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLSServerNameExtension(AOptions.ServerName);
    Inc(n);
  end;
  Groups := AOptions.SupportedGroups;
  if Length(Groups) = 0 then
    Groups := TLS12DefaultSupportedGroups;
  if Length(Groups) > 0 then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLSSupportedGroupsExtension(Groups);
    Inc(n);
  end;
  Sigs := AOptions.SignatureAlgorithms;
  if Length(Sigs) = 0 then
    Sigs := TLS12DefaultSignatureAlgorithms;
  if Length(Sigs) > 0 then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLSSignatureAlgorithmsExtension(Sigs);
    Inc(n);
  end;
  if AOptions.ExtendedMasterSecret then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLSExtendedMasterSecretExtension;
    Inc(n);
  end;
  if AOptions.RenegotiationInfo then
  begin
    SetLength(Result, n + 1);
    Result[n] := EncodeTLSRenegotiationInfoExtension(
      AOptions.RenegotiationInfoData);
    Inc(n);
  end;
end;

function BuildTLS12ClientHelloBody(
  const AOptions: TTLSClientHelloOptions): TBytes;
var
  ClientRand, SessionID, SuiteBytes, ExtBytes: TBytes;
  Suites: TTLSCipherSuites;
  Exts: TTLSExtensions;
  i: Integer;
begin
  ClientRand := AOptions.ClientRandom;
  if Length(ClientRand) = 0 then
    RandomBytes(ClientRand, TLSClientRandomLen)
  else if Length(ClientRand) <> TLSClientRandomLen then
    raise ETLS12Error.CreateFmt(
      'TLS ClientHello: random %d bytes (need %d)',
      [Length(ClientRand), TLSClientRandomLen]);
  SessionID := AOptions.SessionID;
  if Length(SessionID) > TLSMaxSessionIDLen then
    raise ETLS12Error.CreateFmt(
      'TLS ClientHello: session_id %d bytes (maximum %d)',
      [Length(SessionID), TLSMaxSessionIDLen]);
  Suites := AOptions.CipherSuites;
  if Length(Suites) = 0 then
    Suites := TLS12DefaultCipherSuites;
  SuiteBytes := nil;
  for i := 0 to High(Suites) do
    SuiteBytes := TLSBufWord(SuiteBytes, Suites[i]);
  if AOptions.EmptyRenegotiationInfoSCSV then
    SuiteBytes := TLSBufWord(SuiteBytes, TLSCipherEmptyRenegotiationInfoSCSV);
  if AOptions.FallbackSCSV then
    SuiteBytes := TLSBufWord(SuiteBytes, TLSCipherFallbackSCSV);
  if (Length(SuiteBytes) = 0) or (Length(SuiteBytes) > TLSMaxCipherSuitesLen) then
    raise ETLS12Error.CreateFmt(
      'TLS ClientHello: invalid cipher_suites length %d',
      [Length(SuiteBytes)]);
  { Body: version || random || session_id || cipher_suites ||
    compression_methods || [extensions]. }
  Result := TLSBufWord(nil, TLS12Version);
  Result := TLSBufBytes(Result, ClientRand);
  Result := TLSBufByte(Result, Length(SessionID));
  Result := TLSBufBytes(Result, SessionID);
  Result := TLSBufWord(Result, Length(SuiteBytes));
  Result := TLSBufBytes(Result, SuiteBytes);
  { compression_methods: null only (RFC 5246, 7.4.1.2). }
  Result := TLSBufByte(Result, 1);
  Result := TLSBufByte(Result, 0);
  { extensions (optional). }
  Exts := BuildTLS12ClientHelloExtensions(AOptions);
  if Length(Exts) > 0 then
  begin
    ExtBytes := EncodeTLSExtensions(Exts);
    Result := TLSBufBytes(Result, ExtBytes);
  end;
end;

function BuildTLS12ClientHello(
  const AOptions: TTLSClientHelloOptions): TBytes;
begin
  Result := EncodeTLSHandshakeMessage(htClientHello,
    BuildTLS12ClientHelloBody(AOptions));
end;

function ParseTLS12ClientHello(const AData: TBytes): TTLSClientHello;
var
  Pos, SessLen, SuiteLen, CompLen, ExtLen, N, NameLen, i: Integer;
  Ext: TTLSExtension;
begin
  Pos := 0;
  { client_version }
  if Length(AData) < Pos + 2 then
    raise ETLS12Error.Create('TLS ClientHello: truncated client_version');
  Result.Version := TLSReadWordAt(AData, Pos);
  Inc(Pos, 2);
  { random }
  if Length(AData) < Pos + TLSClientRandomLen then
    raise ETLS12Error.Create('TLS ClientHello: truncated random');
  Result.ClientRandom := Copy(AData, Pos, TLSClientRandomLen);
  Inc(Pos, TLSClientRandomLen);
  { session_id }
  if Length(AData) < Pos + 1 then
    raise ETLS12Error.Create('TLS ClientHello: truncated session_id');
  SessLen := AData[Pos];
  Inc(Pos);
  if SessLen > TLSMaxSessionIDLen then
    raise ETLS12Error.CreateFmt(
      'TLS ClientHello: session_id %d bytes (maximum %d)',
      [SessLen, TLSMaxSessionIDLen]);
  if Length(AData) < Pos + SessLen then
    raise ETLS12Error.Create('TLS ClientHello: truncated session_id');
  Result.SessionID := Copy(AData, Pos, SessLen);
  Inc(Pos, SessLen);
  { cipher_suites }
  if Length(AData) < Pos + 2 then
    raise ETLS12Error.Create('TLS ClientHello: truncated cipher_suites');
  SuiteLen := Integer(TLSReadWordAt(AData, Pos));
  Inc(Pos, 2);
  if (SuiteLen < 2) or (SuiteLen mod 2 <> 0) then
    raise ETLS12Error.CreateFmt(
      'TLS ClientHello: invalid cipher_suites length %d', [SuiteLen]);
  if Length(AData) < Pos + SuiteLen then
    raise ETLS12Error.Create('TLS ClientHello: truncated cipher_suites');
  SetLength(Result.CipherSuites, SuiteLen div 2);
  for i := 0 to High(Result.CipherSuites) do
    Result.CipherSuites[i] := TLSReadWordAt(AData, Pos + i * 2);
  Inc(Pos, SuiteLen);
  { compression_methods }
  if Length(AData) < Pos + 1 then
    raise ETLS12Error.Create('TLS ClientHello: truncated compression_methods');
  CompLen := AData[Pos];
  Inc(Pos);
  if Length(AData) < Pos + CompLen then
    raise ETLS12Error.Create('TLS ClientHello: truncated compression_methods');
  Result.CompressionMethods := Copy(AData, Pos, CompLen);
  Inc(Pos, CompLen);
  { extensions (optional) }
  Result.Extensions := nil;
  if Pos < Length(AData) then
  begin
    if Length(AData) < Pos + 2 then
      raise ETLS12Error.Create('TLS ClientHello: truncated extensions');
    ExtLen := Integer(TLSReadWordAt(AData, Pos));
    if Length(AData) < Pos + 2 + ExtLen then
      raise ETLS12Error.Create('TLS ClientHello: truncated extensions');
    Result.Extensions := DecodeTLSExtensions(Copy(AData, Pos, 2 + ExtLen));
  end;
  { --- Derived convenience fields --- }
  Result.ServerName := '';
  if FindTLSExtension(Result.Extensions, TLSExtServerName, Ext) and
     (Length(Ext.Data) >= 5) then
  begin
    N := Integer(TLSReadWordAt(Ext.Data, 0)); { ServerNameList length }
    if (N >= 3) and (N <= Length(Ext.Data) - 2) and
       (Ext.Data[2] = TLSServerNameTypeHostName) then
    begin
      NameLen := Integer(TLSReadWordAt(Ext.Data, 3));
      if NameLen <= Length(Ext.Data) - 5 then
      begin
        SetLength(Result.ServerName, NameLen);
        for i := 0 to NameLen - 1 do
          Result.ServerName[i + 1] := AnsiChar(Ext.Data[5 + i]);
      end;
    end;
  end;
  Result.SupportedGroups := nil;
  if FindTLSExtension(Result.Extensions, TLSExtSupportedGroups, Ext) and
     (Length(Ext.Data) >= 2) then
  begin
    N := Integer(TLSReadWordAt(Ext.Data, 0));
    if (N mod 2 = 0) and (N <= Length(Ext.Data) - 2) then
    begin
      SetLength(Result.SupportedGroups, N div 2);
      for i := 0 to High(Result.SupportedGroups) do
        Result.SupportedGroups[i] := TLSReadWordAt(Ext.Data, 2 + i * 2);
    end;
  end;
  Result.SignatureAlgorithms := nil;
  if FindTLSExtension(Result.Extensions, TLSExtSignatureAlgorithms, Ext) and
     (Length(Ext.Data) >= 2) then
  begin
    N := Integer(TLSReadWordAt(Ext.Data, 0));
    if (N mod 2 = 0) and (N <= Length(Ext.Data) - 2) then
    begin
      SetLength(Result.SignatureAlgorithms, N div 2);
      for i := 0 to High(Result.SignatureAlgorithms) do
        Result.SignatureAlgorithms[i] := TLSReadWordAt(Ext.Data, 2 + i * 2);
    end;
  end;
  Result.ExtendedMasterSecret :=
    FindTLSExtension(Result.Extensions, TLSExtExtendedMasterSecret, Ext);
  Result.RenegotiationInfo :=
    FindTLSExtension(Result.Extensions, TLSExtRenegotiationInfo, Ext);
  Result.RenegotiationInfoData := nil;
  if Result.RenegotiationInfo and (Length(Ext.Data) >= 1) then
  begin
    N := Ext.Data[0];
    if N <= Length(Ext.Data) - 1 then
      Result.RenegotiationInfoData := Copy(Ext.Data, 1, N);
  end;
  Result.EmptyRenegotiationInfoSCSV := False;
  Result.FallbackSCSV := False;
  for i := 0 to High(Result.CipherSuites) do
  begin
    if Result.CipherSuites[i] = TLSCipherEmptyRenegotiationInfoSCSV then
      Result.EmptyRenegotiationInfoSCSV := True;
    if Result.CipherSuites[i] = TLSCipherFallbackSCSV then
      Result.FallbackSCSV := True;
  end;
end;

procedure WriteTLS12ClientHello(ATransport: ITLSTransport;
  const AOptions: TTLSClientHelloOptions);
begin
  WriteTLSFragmented(ATransport, ctHandshake, BuildTLS12ClientHello(AOptions));
end;

{' --- ServerHello/Certificate/ServerKeyExchange: parsing ------------- '}

{ Empty ServerKeyExchange (all fields in initial state). }
function EmptyTLS12ServerKeyExchange: TTLSServerKeyExchange;
begin
  Result.Algorithm := keaUnknown;
  Result.CurveType := 0;
  Result.NamedCurve := 0;
  Result.ECDHEPublicKey := nil;
  Result.DHPrime := nil;
  Result.DHGenerator := nil;
  Result.DHPublic := nil;
  Result.SignatureAlgorithm := 0;
  Result.Signature := nil;
  Result.SignedParams := nil;
end;

function ParseTLS12ServerHello(const AData: TBytes): TTLSServerHello;
var
  Pos, SessLen, ExtLen, N: Integer;
  Ext: TTLSExtension;
begin
  Pos := 0;
  { server_version }
  if Length(AData) < Pos + 2 then
    raise ETLS12Error.Create('TLS ServerHello: truncated server_version');
  Result.Version := TLSReadWordAt(AData, Pos);
  Inc(Pos, 2);
  { random }
  if Length(AData) < Pos + TLSClientRandomLen then
    raise ETLS12Error.Create('TLS ServerHello: truncated random');
  Result.ServerRandom := Copy(AData, Pos, TLSClientRandomLen);
  Inc(Pos, TLSClientRandomLen);
  { session_id }
  if Length(AData) < Pos + 1 then
    raise ETLS12Error.Create('TLS ServerHello: truncated session_id');
  SessLen := AData[Pos];
  Inc(Pos);
  if SessLen > TLSMaxSessionIDLen then
    raise ETLS12Error.CreateFmt(
      'TLS ServerHello: session_id %d bytes (maximum %d)',
      [SessLen, TLSMaxSessionIDLen]);
  if Length(AData) < Pos + SessLen then
    raise ETLS12Error.Create('TLS ServerHello: truncated session_id');
  Result.SessionID := Copy(AData, Pos, SessLen);
  Inc(Pos, SessLen);
  { cipher_suite }
  if Length(AData) < Pos + 2 then
    raise ETLS12Error.Create('TLS ServerHello: truncated cipher_suite');
  Result.CipherSuite := TLSReadWordAt(AData, Pos);
  Inc(Pos, 2);
  { compression_method }
  if Length(AData) < Pos + 1 then
    raise ETLS12Error.Create('TLS ServerHello: truncated compression_method');
  Result.CompressionMethod := AData[Pos];
  Inc(Pos);
  { extensions (optional) }
  Result.Extensions := nil;
  if Pos < Length(AData) then
  begin
    if Length(AData) < Pos + 2 then
      raise ETLS12Error.Create('TLS ServerHello: truncated extensions');
    ExtLen := Integer(TLSReadWordAt(AData, Pos));
    if Length(AData) < Pos + 2 + ExtLen then
      raise ETLS12Error.Create('TLS ServerHello: truncated extensions');
    Result.Extensions := DecodeTLSExtensions(Copy(AData, Pos, 2 + ExtLen));
  end;
  { --- Derived fields from extensions --- }
  Result.ExtendedMasterSecret :=
    FindTLSExtension(Result.Extensions, TLSExtExtendedMasterSecret, Ext);
  Result.RenegotiationInfo :=
    FindTLSExtension(Result.Extensions, TLSExtRenegotiationInfo, Ext);
  Result.RenegotiationInfoData := nil;
  if Result.RenegotiationInfo and (Length(Ext.Data) >= 1) then
  begin
    N := Ext.Data[0];
    if N <= Length(Ext.Data) - 1 then
      Result.RenegotiationInfoData := Copy(Ext.Data, 1, N);
  end;
  Result.ServerNameAcknowledged :=
    FindTLSExtension(Result.Extensions, TLSExtServerName, Ext);
  Result.SessionTicket :=
    FindTLSExtension(Result.Extensions, TLSExtSessionTicket, Ext);
  Result.SessionTicketData := nil;
  if Result.SessionTicket then
    Result.SessionTicketData := Ext.Data;
end;

function ParseTLS12Certificate(const AData: TBytes): TTLSCertificateMessage;
var
  Pos, Total, CertLen, n: Integer;
begin
  Result.Certificates := nil;
  if Length(AData) < 3 then
    raise ETLS12Error.Create(
      'TLS Certificate: truncated certificate list');
  Total := Integer(TLSReadTripleAt(AData, 0));
  if Total > TLSMaxCertificateListLen then
    raise ETLS12Error.CreateFmt(
      'TLS Certificate: list %d bytes exceeds limit %d',
      [Total, TLSMaxCertificateListLen]);
  if Total <> Length(AData) - 3 then
    raise ETLS12Error.CreateFmt(
      'TLS Certificate: declared %d bytes, available %d',
      [Total, Length(AData) - 3]);
  Pos := 3;
  n := 0;
  while Pos < Length(AData) do
  begin
    if Pos + 3 > Length(AData) then
      raise ETLS12Error.Create(
        'TLS Certificate: truncated certificate length');
    CertLen := Integer(TLSReadTripleAt(AData, Pos));
    Inc(Pos, 3);
    if CertLen = 0 then
      raise ETLS12Error.Create('TLS Certificate: empty certificate');
    if Pos + CertLen > Length(AData) then
      raise ETLS12Error.Create('TLS Certificate: truncated certificate');
    SetLength(Result.Certificates, n + 1);
    Result.Certificates[n].Data := Copy(AData, Pos, CertLen);
    Inc(Pos, CertLen);
    Inc(n);
  end;
  { Empty list is allowed at parse level (anonymous/PSK server). }
end;

function ParseTLS12ServerKeyExchange(const AData: TBytes;
  AAlgorithm: TTLSKeyExchangeAlgorithm): TTLSServerKeyExchange;
var
  Pos, FieldLen, SigLen, ParamsStart, ParamsLen: Integer;
  Alg: TTLSKeyExchangeAlgorithm;
begin
  Alg := AAlgorithm;
  if Alg = keaUnknown then
  begin
    { Auto-detection: named_curve (3) as first byte -> ECDHE, otherwise DHE
      (first DHE field is 16-bit dh_p length). }
    if (Length(AData) >= 1) and
       (AData[0] = TLSNamedCurveTypeNamedCurve) then
      Alg := keaECDHE
    else
      Alg := keaDHE;
  end;
  if Alg = keaUnknown then
    raise ETLS12Error.Create('TLS ServerKeyExchange: algorithm not set');

  Result := EmptyTLS12ServerKeyExchange;
  Result.Algorithm := Alg;
  Pos := 0;
  ParamsStart := 0;

  if Alg = keaECDHE then
  begin
    if Length(AData) < Pos + 1 then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated curve_type');
    Result.CurveType := AData[Pos];
    Inc(Pos);
    if Result.CurveType <> TLSNamedCurveTypeNamedCurve then
      raise ETLS12Error.CreateFmt(
        'TLS ServerKeyExchange: unsupported curve_type %d ' +
        '(only named_curve=3 is supported)', [Result.CurveType]);
    if Length(AData) < Pos + 2 then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated named_curve');
    Result.NamedCurve := TLSReadWordAt(AData, Pos);
    Inc(Pos, 2);
    if Length(AData) < Pos + 1 then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated ECPoint');
    FieldLen := AData[Pos];
    Inc(Pos);
    if (FieldLen = 0) or (Length(AData) < Pos + FieldLen) then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated ECPoint');
    Result.ECDHEPublicKey := Copy(AData, Pos, FieldLen);
    Inc(Pos, FieldLen);
    ParamsLen := Pos - ParamsStart;
    Result.SignedParams := Copy(AData, ParamsStart, ParamsLen);
  end
  else
  begin
    { DHE: dh_p || dh_g || dh_Ys, each is opaque<1..2^16-1>. }
    if Length(AData) < Pos + 2 then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated dh_p');
    FieldLen := Integer(TLSReadWordAt(AData, Pos));
    Inc(Pos, 2);
    if (FieldLen = 0) or (Length(AData) < Pos + FieldLen) then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated dh_p');
    Result.DHPrime := Copy(AData, Pos, FieldLen);
    Inc(Pos, FieldLen);

    if Length(AData) < Pos + 2 then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated dh_g');
    FieldLen := Integer(TLSReadWordAt(AData, Pos));
    Inc(Pos, 2);
    if (FieldLen = 0) or (Length(AData) < Pos + FieldLen) then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated dh_g');
    Result.DHGenerator := Copy(AData, Pos, FieldLen);
    Inc(Pos, FieldLen);

    if Length(AData) < Pos + 2 then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated dh_Ys');
    FieldLen := Integer(TLSReadWordAt(AData, Pos));
    Inc(Pos, 2);
    if (FieldLen = 0) or (Length(AData) < Pos + FieldLen) then
      raise ETLS12Error.Create('TLS ServerKeyExchange: truncated dh_Ys');
    Result.DHPublic := Copy(AData, Pos, FieldLen);
    Inc(Pos, FieldLen);

    ParamsLen := Pos - ParamsStart;
    Result.SignedParams := Copy(AData, ParamsStart, ParamsLen);
  end;

  { SignatureAndHashAlgorithm (TLS 1.2, RFC 5246, 7.4.1.4.1). }
  if Length(AData) < Pos + TLSSignatureSchemeLen then
    raise ETLS12Error.Create(
      'TLS ServerKeyExchange: truncated signature algorithm');
  Result.SignatureAlgorithm := TLSReadWordAt(AData, Pos);
  Inc(Pos, TLSSignatureSchemeLen);
  { digitally-signed: length(2) || signature. }
  if Length(AData) < Pos + 2 then
    raise ETLS12Error.Create(
      'TLS ServerKeyExchange: truncated signature length');
  SigLen := Integer(TLSReadWordAt(AData, Pos));
  Inc(Pos, 2);
  if Length(AData) < Pos + SigLen then
    raise ETLS12Error.Create('TLS ServerKeyExchange: truncated signature');
  Result.Signature := Copy(AData, Pos, SigLen);
  Inc(Pos, SigLen);
  if Pos <> Length(AData) then
    raise ETLS12Error.CreateFmt(
      'TLS ServerKeyExchange: %d extra bytes at end',
      [Length(AData) - Pos]);
end;

function ParseTLS12ServerKeyExchange(
  const AData: TBytes): TTLSServerKeyExchange;
begin
  Result := ParseTLS12ServerKeyExchange(AData, keaUnknown);
end;

procedure CheckTLS12ServerHelloDone(const AData: TBytes);
begin
  if Length(AData) <> 0 then
    raise ETLS12Error.CreateFmt(
      'TLS ServerHelloDone: non-empty body (%d bytes)', [Length(AData)]);
end;

function TLS12ServerKeyExchangeSignedData(const AClientRandom,
  AServerRandom: TBytes; const ASKE: TTLSServerKeyExchange): TBytes;
begin
  Result := TLSBufBytes(AClientRandom, AServerRandom);
  Result := TLSBufBytes(Result, ASKE.SignedParams);
end;

function ParseTLS12ServerFlight(const AMessages: TTLSHandshakeMessages;
  out AHello: TTLSServerHello; out ACertificates: TTLSCertificateMessage;
  out AKeyExchange: TTLSServerKeyExchange;
  out AHasCertificates, AHasKeyExchange: Boolean): Boolean;
var
  Msg: TTLSHandshakeMessage;
  HelloDoneSeen: Boolean;
begin
  AHasCertificates := False;
  AHasKeyExchange := False;
  ACertificates.Certificates := nil;
  AKeyExchange := EmptyTLS12ServerKeyExchange;
  Result := False;

  if not FindTLSHandshakeMessage(AMessages, htServerHello, Msg) then
    Exit;
  AHello := ParseTLS12ServerHello(Msg.Body);

  if FindTLSHandshakeMessage(AMessages, htCertificate, Msg) then
  begin
    ACertificates := ParseTLS12Certificate(Msg.Body);
    AHasCertificates := True;
  end;

  if FindTLSHandshakeMessage(AMessages, htServerKeyExchange, Msg) then
  begin
    AKeyExchange := ParseTLS12ServerKeyExchange(Msg.Body);
    AHasKeyExchange := True;
  end;

  HelloDoneSeen := FindTLSHandshakeMessage(AMessages, htServerHelloDone, Msg);
  if HelloDoneSeen then
    CheckTLS12ServerHelloDone(Msg.Body);
  Result := HelloDoneSeen;
end;

{ --- ClientKeyExchange (RFC 5246, 7.4.7; RFC 4492, 5.7) --------------- }

{ Pads big-endian bytes with leading zeros to length ALen; if bytes
  exceed ALen — error. }
function TLS12PadLeft(const AData: TBytes; ALen: Integer): TBytes;
var
  i, Offset: Integer;
begin
  if ALen < 0 then
    raise ETLS12Error.Create('TLS: negative alignment length');
  if Length(AData) > ALen then
    raise ETLS12Error.CreateFmt(
      'TLS: value of %d bytes does not fit in %d bytes',
      [Length(AData), ALen]);
  SetLength(Result, ALen);
  if ALen > 0 then
    FillChar(Result[0], ALen, 0);
  Offset := ALen - Length(AData);
  for i := 0 to Length(AData) - 1 do
    Result[Offset + i] := AData[i];
end;

function BuildTLS12ECDHEClientKeyExchangeBody(const APublicPoint: TBytes): TBytes;
begin
  if (Length(APublicPoint) = 0) or (Length(APublicPoint) > 255) then
    raise ETLS12Error.CreateFmt(
      'TLS ClientKeyExchange: ECPoint length %d (need 1..255)',
      [Length(APublicPoint)]);
  SetLength(Result, 1 + Length(APublicPoint));
  Result[0] := Byte(Length(APublicPoint));
  Move(APublicPoint[0], Result[1], Length(APublicPoint));
end;

function BuildTLS12DHEClientKeyExchangeBody(const AYc: TBytes): TBytes;
begin
  if (Length(AYc) = 0) or (Length(AYc) > $FFFF) then
    raise ETLS12Error.CreateFmt(
      'TLS ClientKeyExchange: DH_Yc length %d (need 1..65535)',
      [Length(AYc)]);
  SetLength(Result, 2 + Length(AYc));
  Result[0] := Byte((Length(AYc) shr 8) and $FF);
  Result[1] := Byte(Length(AYc) and $FF);
  Move(AYc[0], Result[2], Length(AYc));
end;

function ParseTLS12ClientKeyExchange(const AData: TBytes;
  AAlgorithm: TTLSKeyExchangeAlgorithm; out APublicKey: TBytes): Boolean;
var
  Len: Integer;
begin
  APublicKey := nil;
  Result := False;
  case AAlgorithm of
    keaECDHE:
      begin
        if Length(AData) < 1 then
          Exit;
        Len := AData[0];
        if (Len = 0) or (Length(AData) <> 1 + Len) then
          Exit;
        APublicKey := Copy(AData, 1, Len);
      end;
    keaDHE:
      begin
        if Length(AData) < 2 then
          Exit;
        Len := Integer(TLSReadWordAt(AData, 0));
        if (Len = 0) or (Length(AData) <> 2 + Len) then
          Exit;
        APublicKey := Copy(AData, 2, Len);
      end;
  else
    Exit;
  end;
  Result := True;
end;

{ --- TTLS12ECDHEClientKey -------------------------------------------- }

class function TTLS12ECDHEClientKey.IsSupportedGroup(
  ANamedGroup: TTLSNamedGroup): Boolean;
begin
  Result := (ANamedGroup = TLSNamedGroupSecp256r1) or
    (ANamedGroup = TLSNamedGroupSecp384r1);
end;

class function TTLS12ECDHEClientKey.FieldSize(
  ANamedGroup: TTLSNamedGroup): Integer;
begin
  case ANamedGroup of
    TLSNamedGroupSecp256r1: Result := 32;
    TLSNamedGroupSecp384r1: Result := 48;
  else
    Result := 0;
  end;
end;

constructor TTLS12ECDHEClientKey.Create(ANamedGroup: TTLSNamedGroup);
begin
  inherited Create;
  if not IsSupportedGroup(ANamedGroup) then
    raise ETLS12Error.CreateFmt(
      'TLS ECDHE: unsupported group 0x%.4x', [ANamedGroup]);
  FNamedGroup := ANamedGroup;
  case ANamedGroup of
    TLSNamedGroupSecp256r1: FCurve := CurveP256;
    TLSNamedGroupSecp384r1: FCurve := CurveP384;
  else
    raise ETLS12Error.Create('TLS ECDHE: curve not found');
  end;
  FKeyPair := GenerateKeyPair(FCurve);
end;

destructor TTLS12ECDHEClientKey.Destroy;
begin
  if FKeyPair <> nil then
    FKeyPair.Free;
  if FCurve <> nil then
    FCurve.Free;
  inherited;
end;

function TTLS12ECDHEClientKey.PublicPoint: TBytes;
begin
  Result := EncodePoint(FCurve, FKeyPair.PublicKey);
end;

function TTLS12ECDHEClientKey.ClientKeyExchangeBody: TBytes;
begin
  Result := BuildTLS12ECDHEClientKeyExchangeBody(PublicPoint);
end;

function TTLS12ECDHEClientKey.PremasterSecret(
  const AServerPublicPoint: TBytes): TBytes;
var
  PeerPoint, Shared: TECPoint;
begin
  if Length(AServerPublicPoint) = 0 then
    raise ETLS12Error.Create('TLS ECDHE: empty server point');
  try
    PeerPoint := DecodePoint(FCurve, AServerPublicPoint);
  except
    on E: EBNError do
      raise ETLS12Error.Create(
        'TLS ECDHE: failed to parse server point: ' + E.Message);
  end;
  try
    if PeerPoint.Infinity then
      raise ETLS12Error.Create('TLS ECDHE: server point at infinity');
    if not IsOnCurve(FCurve, PeerPoint) then
      raise ETLS12Error.Create(
        'TLS ECDHE: server point is not on the curve');
    Shared := ComputeSharedSecret(FCurve, FKeyPair.PrivateKey, PeerPoint);
    try
      if Shared.Infinity then
        raise ETLS12Error.Create(
          'TLS ECDHE: shared secret is the point at infinity');
      { RFC 4492, 5.10: premaster secret is the X-coordinate of the shared point,
        padded with leading zeros to the field size. }
      Result := TLS12PadLeft(Shared.X.ToBytes(True),
        FieldSize(FNamedGroup));
    finally
      Shared.Free;
    end;
  finally
    PeerPoint.Free;
  end;
end;

{ --- TTLS12DHEClientKey ---------------------------------------------- }

constructor TTLS12DHEClientKey.Create;
begin
  inherited Create;
  FKey := TDHKey.Create;
  FPrimeLen := 0;
end;

destructor TTLS12DHEClientKey.Destroy;
begin
  if FKey <> nil then
    FKey.Free;
  inherited;
end;

procedure TTLS12DHEClientKey.InitFromServerParams(const APrime,
  AGenerator: TBytes);
begin
  if Length(APrime) < 2 then
    raise ETLS12Error.Create('TLS DHE: empty/truncated dh_p');
  if Length(AGenerator) = 0 then
    raise ETLS12Error.Create('TLS DHE: empty dh_g');
  if FKey.P <> nil then
    FKey.P.Free;
  if FKey.G <> nil then
    FKey.G.Free;
  FKey.P := TBN.FromBytes(APrime, True);
  FKey.G := TBN.FromBytes(AGenerator, True);
  FPrimeLen := (FKey.P.BitLength + 7) div 8;
  if FPrimeLen = 0 then
    raise ETLS12Error.Create('TLS DHE: zero dh_p');
  FKey.Generate;
end;

function TTLS12DHEClientKey.PublicKey: TBytes;
begin
  if FKey.Pub = nil then
    raise ETLS12Error.Create('TLS DHE: key not initialized');
  { Compatibility (OpenSSL): Yc is padded with leading zeros to the length of p. }
  Result := TLS12PadLeft(FKey.Pub.ToBytes(True), FPrimeLen);
end;

function TTLS12DHEClientKey.ClientKeyExchangeBody: TBytes;
begin
  Result := BuildTLS12DHEClientKeyExchangeBody(PublicKey);
end;

function TTLS12DHEClientKey.PremasterSecret(
  const AServerPublic: TBytes): TBytes;
var
  PeerPub, Secret, One, Pm1: TBN;
begin
  if (FKey.P = nil) or (FKey.Priv = nil) then
    raise ETLS12Error.Create('TLS DHE: key not initialized');
  if Length(AServerPublic) = 0 then
    raise ETLS12Error.Create('TLS DHE: empty server Ys');
  PeerPub := TBN.FromBytes(AServerPublic, True);
  try
    if not FKey.ValidatePeerPub(PeerPub) then
      raise ETLS12Error.Create('TLS DHE: server Ys out of range [2, p-2]');
    Secret := FKey.ComputeSecret(PeerPub);
    try
      One := TBN.FromQWord(1);
      Pm1 := FKey.P.Sub(One);
      try
        if (Secret.Compare(One) <= 0) or Secret.Equal(Pm1) then
          raise ETLS12Error.Create('TLS DHE: invalid shared secret');
      finally
        One.Free;
        Pm1.Free;
      end;
      { RFC 5246, 8.1.2: leading zero bytes are stripped (as in
        OpenSSL DH_compute_key). TBN.ToBytes returns the minimal form. }
      Result := Secret.ToBytes(True);
    finally
      Secret.Free;
    end;
  finally
    PeerPub.Free;
  end;
end;


{ --- TTLSStreamTransport --------------------------------------------- }

constructor TTLSStreamTransport.Create(AStream: TStream);
begin
  inherited Create;
  if AStream = nil then
    raise ETLS12Error.Create('TLS transport: stream not set');
  FStream := AStream;
end;

function TTLSStreamTransport.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  if ACount < 0 then
    raise ETLS12Error.Create('TLS transport: negative read length');
  if ACount = 0 then
    Exit(0);
  Result := FStream.Read(ABuffer, ACount);
end;

function TTLSStreamTransport.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  if ACount < 0 then
    raise ETLS12Error.Create('TLS transport: negative write length');
  if ACount = 0 then
    Exit(0);
  Result := FStream.Write(ABuffer, ACount);
end;

function TTLSStreamTransport.BytesAvailable: LongInt;
begin
  { For TStream, everything remaining from the current position to the end is available. }
  Result := FStream.Size - FStream.Position;
  if Result < 0 then
    Result := 0;
end;


{ --- Server flight verification (RFC 5246, 7.4.3; RFC 5280) -------- }

function TLS12SignatureSchemeKeyAlgorithm(AScheme: TTLSSignatureScheme): Byte;
begin
  Result := Byte(AScheme and $00FF);
end;

function TLS12SignatureSchemeX509OID(AScheme: TTLSSignatureScheme): string;
begin
  case AScheme of
    TLSSigRSA_PKCS1_SHA256: Result := '1.2.840.113549.1.1.11';
    TLSSigRSA_PKCS1_SHA384: Result := '1.2.840.113549.1.1.12';
    TLSSigRSA_PKCS1_SHA512: Result := '1.2.840.113549.1.1.13';
    TLSSigECDSA_Secp256r1_SHA256: Result := '1.2.840.10045.4.3.2';
    TLSSigECDSA_Secp384r1_SHA384: Result := '1.2.840.10045.4.3.3';
    TLSSigECDSA_Secp521r1_SHA512: Result := '1.2.840.10045.4.3.4';
  else
    Result := '';
  end;
end;

function TLS12SignatureSchemeSupported(AScheme: TTLSSignatureScheme): Boolean;
begin
  Result := TLS12SignatureSchemeX509OID(AScheme) <> '';
end;

function TLS12SignatureSchemeName(AScheme: TTLSSignatureScheme): string;
begin
  case AScheme of
    TLSSigRSA_PKCS1_SHA256: Result := 'rsa_pkcs1_sha256';
    TLSSigRSA_PKCS1_SHA384: Result := 'rsa_pkcs1_sha384';
    TLSSigRSA_PKCS1_SHA512: Result := 'rsa_pkcs1_sha512';
    TLSSigECDSA_Secp256r1_SHA256: Result := 'ecdsa_secp256r1_sha256';
    TLSSigECDSA_Secp384r1_SHA384: Result := 'ecdsa_secp384r1_sha384';
    TLSSigECDSA_Secp521r1_SHA512: Result := 'ecdsa_secp521r1_sha512';
    TLSSigRSA_PSS_RSAE_SHA256: Result := 'rsa_pss_rsae_sha256';
    TLSSigRSA_PSS_RSAE_SHA384: Result := 'rsa_pss_rsae_sha384';
    TLSSigRSA_PSS_RSAE_SHA512: Result := 'rsa_pss_rsae_sha512';
    TLSSigEd25519: Result := 'ed25519';
  else
    Result := Format('unknown_signature_scheme(0x%.4x)', [AScheme]);
  end;
end;

function VerifyTLS12Signature(const ACert: TX509Cert;
  const AData, ASignature: TBytes; AScheme: TTLSSignatureScheme): Boolean;
var
  oid: string;
begin
  Result := False;
  if ACert = nil then Exit;
  if Length(AData) = 0 then Exit;
  if Length(ASignature) = 0 then Exit;
  if not TLS12SignatureSchemeSupported(AScheme) then Exit;

  { The certificate key type must match the signature scheme:
    1 = rsa, 3 = ecdsa (RFC 5246, 7.4.1.4.1). }
  case TLS12SignatureSchemeKeyAlgorithm(AScheme) of
    1: if ACert.SPKI.KeyType <> pkRSA then Exit;
    3: if ACert.SPKI.KeyType <> pkEC then Exit;
  else
    Exit;
  end;

  oid := TLS12SignatureSchemeX509OID(AScheme);
  Result := VerifyDataSignature(ACert, AData, ASignature, oid);
end;

function VerifyTLS12ServerKeyExchange(const ALeafCert: TX509Cert;
  const AClientRandom, AServerRandom: TBytes;
  const ASKE: TTLSServerKeyExchange): Boolean;
var
  signedData: TBytes;
begin
  if ALeafCert = nil then
    raise ETLS12Error.Create(
      'TLS ServerKeyExchange: server certificate not set');
  if not TLS12SignatureSchemeSupported(ASKE.SignatureAlgorithm) then
    raise ETLS12Error.CreateFmt(
      'TLS ServerKeyExchange: unsupported signature scheme %s',
      [TLS12SignatureSchemeName(ASKE.SignatureAlgorithm)]);
  if Length(ASKE.SignedParams) = 0 then Exit(False);
  if Length(ASKE.Signature) = 0 then Exit(False);

  { The server signs client_random || server_random || ServerKeyExchange
    params (RFC 5246, 7.4.3). }
  signedData := TLS12ServerKeyExchangeSignedData(
    AClientRandom, AServerRandom, ASKE);
  Result := VerifyTLS12Signature(ALeafCert, signedData, ASKE.Signature,
    ASKE.SignatureAlgorithm);
end;

function VerifyTLS12ServerKeyExchange(const AChain: TTLS12CertChain;
  const AClientRandom, AServerRandom: TBytes;
  const ASKE: TTLSServerKeyExchange): Boolean;
begin
  if (AChain = nil) or (AChain.Leaf = nil) then
    raise ETLS12Error.Create(
      'TLS ServerKeyExchange: certificate chain is empty');
  Result := VerifyTLS12ServerKeyExchange(
    AChain.Leaf, AClientRandom, AServerRandom, ASKE);
end;

{ --- TTLS12CertChain ------------------------------------------------ }

constructor TTLS12CertChain.Create;
begin
  inherited Create;
  FCerts := nil;
end;

destructor TTLS12CertChain.Destroy;
var
  i: LongInt;
begin
  for i := 0 to Length(FCerts) - 1 do
    FCerts[i].Free;
  FCerts := nil;
  inherited Destroy;
end;

function TTLS12CertChain.GetCount: LongInt;
begin
  Result := Length(FCerts);
end;

function TTLS12CertChain.GetLeaf: TX509Cert;
begin
  if Length(FCerts) = 0 then
    Result := nil
  else
    Result := FCerts[0];
end;

function TTLS12CertChain.Cert(AIndex: LongInt): TX509Cert;
begin
  if (AIndex < 0) or (AIndex >= Length(FCerts)) then
    raise ETLS12Error.CreateFmt(
      'TLS Certificate: index %d out of range (0..%d)',
      [AIndex, Length(FCerts) - 1]);
  Result := FCerts[AIndex];
end;

procedure TTLS12CertChain.Parse(const ACertificates: TTLSCertificateMessage);
var
  i: LongInt;
  parsed: TX509Cert;
begin
  { Freeing previous contents — repeated Parse is allowed. }
  for i := 0 to Length(FCerts) - 1 do
    FCerts[i].Free;
  FCerts := nil;

  for i := 0 to Length(ACertificates.Certificates) - 1 do
  begin
    try
      parsed := ParseCertificate(ACertificates.Certificates[i].Data);
    except
      on E: ETLS12Error do
        raise;
      on E: Exception do
        raise ETLS12Error.CreateFmt(
          'TLS Certificate: error parsing certificate #%d: %s',
          [i, E.Message]);
    end;
    SetLength(FCerts, Length(FCerts) + 1);
    FCerts[Length(FCerts) - 1] := parsed;
  end;
end;

function TTLS12CertChain.Verify(const ATrustStore: TCertStore;
  AHops: LongInt; ANow: TDateTime): TVerifyResult;
var
  store: TCertStore;
  anchor: TX509Cert;
  aki: TBytes;
  i: LongInt;
begin
  Result.OK := False;
  Result.Reason := '';
  Result.ChainLen := 0;
  if Leaf = nil then
  begin
    Result.Reason := 'empty certificate chain';
    Exit;
  end;

  { VerifyChain accepts a self-signed certificate as root without
    verifying it against the store. For TLS this is unacceptable: a self-signed
    leaf must match a trusted root from ATrustStore, otherwise
    any self-signed certificate would pass verification. }
  if Leaf.Issuer.ToNameString = Leaf.Subject.ToNameString then
  begin
    anchor := nil;
    if ATrustStore <> nil then
    begin
      aki := Leaf.GetAuthorityKeyIdentifier;
      if Length(aki) > 0 then
        anchor := ATrustStore.FindBySKI(aki);
      if anchor = nil then
        anchor := ATrustStore.FindBySubject(Leaf.Subject.ToNameString);
    end;
    if anchor = nil then
    begin
      Result.Reason := 'self-signed leaf is not a trusted root';
      Exit;
    end;
  end;

  store := TCertStore.Create;
  try
    { Trusted CAs from the store. }
    if ATrustStore <> nil then
      for i := 0 to ATrustStore.Count - 1 do
        store.Add(ATrustStore.At(i));
    { Intermediate certificates sent by the server (without leaf).
      We do not add self-signed roots: only certificates from
      ATrustStore can be trusted. }
    for i := 1 to Count - 1 do
      if FCerts[i].Issuer.ToNameString <> FCerts[i].Subject.ToNameString then
        store.Add(FCerts[i]);
    Result := VerifyChain(store, Leaf, AHops, ANow);
  finally
    store.Free;  { store holds references and does not own the certificates }
  end;
end;

function ParseTLS12CertChain(
  const ACertificates: TTLSCertificateMessage): TTLS12CertChain;
begin
  Result := TTLS12CertChain.Create;
  try
    Result.Parse(ACertificates);
  except
    Result.Free;
    raise;
  end;
end;

{ --- ChangeCipherSpec (RFC 5246, 7.1) -------------------------------- }

function EncodeTLSChangeCipherSpec: TBytes;
begin
  SetLength(Result, 1);
  Result[0] := TLSChangeCipherSpec;
end;

procedure CheckTLSChangeCipherSpec(const ACipherSpec: TBytes);
begin
  if (Length(ACipherSpec) <> 1) or (ACipherSpec[0] <> TLSChangeCipherSpec) then
    raise ETLS12Error.CreateFmt(
      'TLS ChangeCipherSpec: expected byte 0x%02X, got %d bytes',
      [TLSChangeCipherSpec, Length(ACipherSpec)]);
end;

procedure WriteTLS12ChangeCipherSpec(ATransport: ITLSTransport;
  AVersion: Word);
begin
  WriteTLSRecord(ATransport, ctChangeCipherSpec,
    EncodeTLSChangeCipherSpec, AVersion);
end;

procedure ReadTLS12ChangeCipherSpec(ATransport: ITLSTransport);
var
  Rec: TTLSRecord;
begin
  Rec := ReadTLSRecord(ATransport);
  if Rec.ContentType <> ctChangeCipherSpec then
    raise ETLS12Error.CreateFmt(
      'TLS ChangeCipherSpec: expected record type %d, got %d',
      [Ord(ctChangeCipherSpec), Ord(Rec.ContentType)]);
  CheckTLSChangeCipherSpec(Rec.Fragment);
end;

{ --- Finished / VerifyData (RFC 5246, 7.4.9) ------------------------- }

function TLS12CipherSuiteHashKind(ASuite: TTLSCipherSuite): THashKind;
begin
  case ASuite of
    TLSCipherRSA_AES256GCM_SHA384,
    TLSCipherDHE_RSA_AES256GCM_SHA384,
    TLSCipherECDHE_ECDSA_AES256GCM_SHA384,
    TLSCipherECDHE_RSA_AES256GCM_SHA384:
      Result := hkSHA384;
    TLSCipherRSA_AES128GCM_SHA256,
    TLSCipherDHE_RSA_AES128GCM_SHA256,
    TLSCipherECDHE_ECDSA_AES128GCM_SHA256,
    TLSCipherECDHE_RSA_AES128GCM_SHA256,
    TLSCipherECDHE_RSA_CHACHA20POLY1305_SHA256,
    TLSCipherECDHE_ECDSA_CHACHA20POLY1305_SHA256:
      Result := hkSHA256;
  else
    raise ETLS12Error.CreateFmt(
      'TLS 1.2 Finished: unknown cipher suite 0x%.4X', [ASuite]);
  end;
end;

function TLS12TranscriptHash(AKind: THashKind;
  const ATranscript: TBytes): TBytes;
begin
  case AKind of
    hkSHA256: Result := SHA256(ATranscript);
    hkSHA384: Result := SHA384(ATranscript);
    hkSHA512: Result := SHA512(ATranscript);
  else
    raise ETLS12Error.Create('TLS 1.2 Finished: unsupported PRF hash');
  end;
end;

function TLS12VerifyData(AKind: THashKind; const AMasterSecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;
begin
  Result := TLS12PRF(AKind, AMasterSecret, ALabel,
    TLS12TranscriptHash(AKind, ATranscript), TLSFinishedVerifyDataLen);
end;

{ Comparison without early exit: does not reveal the position of difference. }
function TLSConstantTimeEquals(const A, B: TBytes): Boolean;
var
  i: Integer;
  Diff: Byte;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  Diff := 0;
  for i := 0 to High(A) do
    Diff := Diff or (A[i] xor B[i]);
  Result := Diff = 0;
end;

function TLS12VerifyFinished(AKind: THashKind; const AMasterSecret: TBytes;
  const ALabel: AnsiString; const ATranscript,
  AVerifyData: TBytes): Boolean;
begin
  Result := TLSConstantTimeEquals(
    TLS12VerifyData(AKind, AMasterSecret, ALabel, ATranscript),
    AVerifyData);
end;

function EncodeTLS12FinishedBody(const AVerifyData: TBytes): TBytes;
begin
  if Length(AVerifyData) <> TLSFinishedVerifyDataLen then
    raise ETLS12Error.CreateFmt(
      'TLS Finished: verify_data length %d, expected %d',
      [Length(AVerifyData), TLSFinishedVerifyDataLen]);
  Result := Copy(AVerifyData, 0, TLSFinishedVerifyDataLen);
end;

function BuildTLS12Finished(const AVerifyData: TBytes): TBytes;
begin
  Result := EncodeTLSHandshakeMessage(htFinished,
    EncodeTLS12FinishedBody(AVerifyData));
end;

function ParseTLS12FinishedBody(const ABody: TBytes): TBytes;
begin
  if Length(ABody) <> TLSFinishedVerifyDataLen then
    raise ETLS12Error.CreateFmt(
      'TLS Finished: body %d bytes, expected %d',
      [Length(ABody), TLSFinishedVerifyDataLen]);
  Result := Copy(ABody, 0, TLSFinishedVerifyDataLen);
end;

function TLS12FinishedMessage(AKind: THashKind;
  const AMasterSecret: TBytes; const ALabel: AnsiString;
  const ATranscript: TBytes): TBytes;
begin
  Result := BuildTLS12Finished(
    TLS12VerifyData(AKind, AMasterSecret, ALabel, ATranscript));
end;

function TLS12CheckFinished(AKind: THashKind;
  const AMasterSecret: TBytes; const ALabel: AnsiString;
  const ATranscript, ABody: TBytes): Boolean;
begin
  Result := TLS12VerifyFinished(AKind, AMasterSecret, ALabel, ATranscript,
    ParseTLS12FinishedBody(ABody));
end;

{ --- Alert (RFC 5246, 7.2) ------------------------------------------- }

function TLSAlertLevelToByte(ALevel: TTLSAlertLevel): Byte;
begin
  Result := Byte(Ord(ALevel));
end;

function ByteToTLSAlertLevel(AValue: Byte): TTLSAlertLevel;
begin
  case AValue of
    1: Result := alWarning;
    2: Result := alFatal;
  else
    raise ETLS12Error.CreateFmt('TLS Alert: unknown level %d', [AValue]);
  end;
end;

function TLSAlertDescriptionToByte(ADescription: TTLSAlertDescription): Byte;
begin
  Result := Byte(Ord(ADescription));
end;

function ByteToTLSAlertDescription(AValue: Byte): TTLSAlertDescription;
begin
  case AValue of
    0: Result := adCloseNotify;
    10: Result := adUnexpectedMessage;
    20: Result := adBadRecordMac;
    21: Result := adDecryptionFailed;
    22: Result := adRecordOverflow;
    30: Result := adDecompressionFailure;
    40: Result := adHandshakeFailure;
    41: Result := adNoCertificate;
    42: Result := adBadCertificate;
    43: Result := adUnsupportedCertificate;
    44: Result := adCertificateRevoked;
    45: Result := adCertificateExpired;
    46: Result := adCertificateUnknown;
    47: Result := adIllegalParameter;
    48: Result := adUnknownCa;
    49: Result := adAccessDenied;
    50: Result := adDecodeError;
    51: Result := adDecryptError;
    60: Result := adExportRestriction;
    70: Result := adProtocolVersion;
    71: Result := adInsufficientSecurity;
    80: Result := adInternalError;
    90: Result := adUserCanceled;
    100: Result := adNoRenegotiation;
    110: Result := adUnsupportedExtension;
  else
    raise ETLS12Error.CreateFmt(
      'TLS Alert: unknown description %d', [AValue]);
  end;
end;

function IsKnownAlertDescription(AValue: Byte): Boolean;
var
  Desc: TTLSAlertDescription;
begin
  try
    Desc := ByteToTLSAlertDescription(AValue);
    Result := Ord(Desc) = AValue;
  except
    on E: ETLS12Error do
      Result := False;
  end;
end;

function TLSAlertLevelName(ALevel: TTLSAlertLevel): string;
begin
  case ALevel of
    alWarning: Result := 'warning';
    alFatal: Result := 'fatal';
  else
    Result := Format('unknown(%d)', [Ord(ALevel)]);
  end;
end;

function TLSAlertDescriptionName(ADescription: TTLSAlertDescription): string;
begin
  case ADescription of
    adCloseNotify: Result := 'close_notify';
    adUnexpectedMessage: Result := 'unexpected_message';
    adBadRecordMac: Result := 'bad_record_mac';
    adDecryptionFailed: Result := 'decryption_failed';
    adRecordOverflow: Result := 'record_overflow';
    adDecompressionFailure: Result := 'decompression_failure';
    adHandshakeFailure: Result := 'handshake_failure';
    adNoCertificate: Result := 'no_certificate';
    adBadCertificate: Result := 'bad_certificate';
    adUnsupportedCertificate: Result := 'unsupported_certificate';
    adCertificateRevoked: Result := 'certificate_revoked';
    adCertificateExpired: Result := 'certificate_expired';
    adCertificateUnknown: Result := 'certificate_unknown';
    adIllegalParameter: Result := 'illegal_parameter';
    adUnknownCa: Result := 'unknown_ca';
    adAccessDenied: Result := 'access_denied';
    adDecodeError: Result := 'decode_error';
    adDecryptError: Result := 'decrypt_error';
    adExportRestriction: Result := 'export_restriction';
    adProtocolVersion: Result := 'protocol_version';
    adInsufficientSecurity: Result := 'insufficient_security';
    adInternalError: Result := 'internal_error';
    adUserCanceled: Result := 'user_canceled';
    adNoRenegotiation: Result := 'no_renegotiation';
    adUnsupportedExtension: Result := 'unsupported_extension';
  else
    Result := Format('unknown_alert(%d)', [Ord(ADescription)]);
  end;
end;

function EncodeTLSAlert(ALevel: TTLSAlertLevel;
  ADescription: TTLSAlertDescription): TBytes;
begin
  SetLength(Result, 2);
  Result[0] := TLSAlertLevelToByte(ALevel);
  Result[1] := TLSAlertDescriptionToByte(ADescription);
end;

function DecodeTLSAlert(const AData: TBytes): TTLSAlert;
begin
  if Length(AData) <> 2 then
    raise ETLS12Error.CreateFmt(
      'TLS Alert: body length %d, expected 2', [Length(AData)]);
  Result.Level := ByteToTLSAlertLevel(AData[0]);
  Result.Description := ByteToTLSAlertDescription(AData[1]);
end;

procedure WriteTLS12Alert(ATransport: ITLSTransport; ALevel: TTLSAlertLevel;
  ADescription: TTLSAlertDescription; AVersion: Word);
begin
  WriteTLSRecord(ATransport, ctAlert,
    EncodeTLSAlert(ALevel, ADescription), AVersion);
end;

function ReadTLS12Alert(ATransport: ITLSTransport): TTLSAlert;
var
  Rec: TTLSRecord;
begin
  Rec := ReadTLSRecord(ATransport);
  if Rec.ContentType <> ctAlert then
    raise ETLS12Error.CreateFmt(
      'TLS Alert: expected record type %d, got %d',
      [Ord(ctAlert), Ord(Rec.ContentType)]);
  Result := DecodeTLSAlert(Rec.Fragment);
end;

function TLS12AlertIsFatal(const AAlert: TTLSAlert): Boolean;
begin
  Result := AAlert.Level = alFatal;
end;

{ --- TTLS12Client ---------------------------------------------------- }

function TTLS12Client.GetHandshakeDone: Boolean;
begin
  Result := FHandshakeDone;
end;

function TTLS12Client.GetCipherSuite: TTLSCipherSuite;
begin
  Result := FCipherSuite;
end;

function TTLS12Client.GetPendingBytes: LongInt;
begin
  Result := Length(FRecvBuf) - FRecvPos;
  if Result < 0 then
    Result := 0;
end;

function TTLS12Client.CertChain: TTLS12CertChain;
begin
  Result := FChain;
end;

constructor TTLS12Client.Create;
begin
  inherited Create;
  FOptions := DefaultTLS12ClientHelloOptions;
  FBuffer := TTLSHandshakeBuffer.Create;
  FChain := nil;
  FTrustStore := nil;
  FConnected := False;
  FHandshakeDone := False;
  FCipherSuite := 0;
  FAEADMode := aeadAES128GCM;
  FHashKind := hkSHA256;
  FClientWriteKey := nil;
  FServerWriteKey := nil;
  FClientWriteIV := nil;
  FServerWriteIV := nil;
  FClientSeq := 0;
  FServerSeq := 0;
  FMasterSecret := nil;
  FRecvBuf := nil;
  FRecvPos := 0;
end;

destructor TTLS12Client.Destroy;
begin
  if FChain <> nil then
    FChain.Free;
  if FBuffer <> nil then
    FBuffer.Free;
  inherited Destroy;
end;

procedure TTLS12Client.DoHandshake;
var
  ClientRandom, HelloBody, CKEBody, Premaster, SessionHash: TBytes;
  FinishedBody, FinMsg, ClientVD, ServerVD, Frag, Plain: TBytes;
  ServerMsgs: TTLSHandshakeMessages;
  Hello: TTLSServerHello;
  CertMsg: TTLSCertificateMessage;
  SKE: TTLSServerKeyExchange;
  HasCert, HasSKE: Boolean;
  VR: TVerifyResult;
  EKey: TTLS12ECDHEClientKey;
  DKey: TTLS12DHEClientKey;
  KB: TTLS12KeyBlock;
  Rec: TTLSRecord;
  Fin: TTLSHandshakeMessage;
begin
  FBuffer.Clear;

  { --- ClientHello --- }
  RandomBytes(ClientRandom, TLSClientRandomLen);
  FOptions.ClientRandom := ClientRandom;
  HelloBody := BuildTLS12ClientHelloBody(FOptions);
  WriteTLSHandshakeMessage(FTransport, htClientHello, HelloBody);
  FBuffer.AppendTranscript(htClientHello, HelloBody);

  { --- Server flight: ServerHello, Certificate, ServerKeyExchange,
    ServerHelloDone --- }
  if not ReadTLSHandshakeFlight(FTransport, FBuffer,
    [htServerHelloDone], ServerMsgs) then
    raise ETLS12Error.Create(
      'TLS 1.2: server closed connection before ServerHelloDone');
  if not ParseTLS12ServerFlight(ServerMsgs, Hello, CertMsg, SKE,
    HasCert, HasSKE) then
    raise ETLS12Error.Create(
      'TLS 1.2: failed to parse server flight');
  if not HasCert then
    raise ETLS12Error.Create(
      'TLS 1.2: server did not send Certificate');
  if not HasSKE then
    raise ETLS12Error.Create(
      'TLS 1.2: server did not send ServerKeyExchange');

  { --- Parse and verify certificate chain --- }
  if FChain <> nil then
    FChain.Free;
  FChain := ParseTLS12CertChain(CertMsg);
  if (FTrustStore <> nil) and (FChain.Count > 0) then
  begin
    VR := FChain.Verify(FTrustStore);
    if not VR.OK then
      raise ETLS12Error.CreateFmt(
        'TLS 1.2: certificate chain verification failed: %s', [VR.Reason]);
  end;

  { --- Verify ServerKeyExchange signature --- }
  if not VerifyTLS12ServerKeyExchange(FChain, ClientRandom,
    Hello.ServerRandom, SKE) then
    raise ETLS12Error.Create(
      'TLS 1.2: ServerKeyExchange signature is invalid');

  { --- Negotiated parameters --- }
  FCipherSuite := Hello.CipherSuite;
  FAEADMode := TLS12CipherSuiteAEADMode(FCipherSuite);
  FHashKind := TLS12CipherSuiteHashKind(FCipherSuite);

  { --- ClientKeyExchange and premaster secret --- }
  Premaster := nil;
  if SKE.Algorithm = keaECDHE then
  begin
    EKey := TTLS12ECDHEClientKey.Create(SKE.NamedCurve);
    try
      CKEBody := EKey.ClientKeyExchangeBody;
      WriteTLSHandshakeMessage(FTransport, htClientKeyExchange, CKEBody);
      FBuffer.AppendTranscript(htClientKeyExchange, CKEBody);
      Premaster := EKey.PremasterSecret(SKE.ECDHEPublicKey);
    finally
      EKey.Free;
    end;
  end
  else if SKE.Algorithm = keaDHE then
  begin
    DKey := TTLS12DHEClientKey.Create;
    try
      DKey.InitFromServerParams(SKE.DHPrime, SKE.DHGenerator);
      CKEBody := DKey.ClientKeyExchangeBody;
      WriteTLSHandshakeMessage(FTransport, htClientKeyExchange, CKEBody);
      FBuffer.AppendTranscript(htClientKeyExchange, CKEBody);
      Premaster := DKey.PremasterSecret(SKE.DHPublic);
    finally
      DKey.Free;
    end;
  end
  else
    raise ETLS12Error.CreateFmt(
      'TLS 1.2: unsupported key exchange algorithm %d',
      [Ord(SKE.Algorithm)]);

  { --- Master secret and key block --- }
  if Hello.ExtendedMasterSecret then
  begin
    SessionHash := TLS12TranscriptHash(FHashKind, FBuffer.Transcript);
    FMasterSecret := TLS12ExtendedMasterSecret(FHashKind, Premaster,
      SessionHash);
  end
  else
    FMasterSecret := TLS12MasterSecret(FHashKind, Premaster,
      ClientRandom, Hello.ServerRandom);
  KB := TLS12KeyBlock(FHashKind, FMasterSecret, Hello.ServerRandom,
    ClientRandom, 0, TLSAEADKeyLength(FAEADMode),
    TLSAEADFixedIvLength(FAEADMode));
  FClientWriteKey := KB.ClientWriteKey;
  FServerWriteKey := KB.ServerWriteKey;
  FClientWriteIV := KB.ClientWriteIV;
  FServerWriteIV := KB.ServerWriteIV;
  FClientSeq := 0;
  FServerSeq := 0;

  { --- Client CCS + Finished (encrypted) --- }
  ClientVD := TLS12VerifyData(FHashKind, FMasterSecret,
    TLSFinishedLabelClient, FBuffer.Transcript);
  FinishedBody := EncodeTLS12FinishedBody(ClientVD);
  FBuffer.AppendTranscript(htFinished, FinishedBody);
  FinMsg := BuildTLS12Finished(ClientVD);
  WriteTLS12ChangeCipherSpec(FTransport);
  Frag := TLSAEADEncryptFragment(FAEADMode, FClientWriteKey,
    FClientWriteIV, QWord(0), ctHandshake, TLS12Version, FinMsg);
  WriteTLSRecord(FTransport, ctHandshake, Frag);
  Inc(FClientSeq);

  { --- Server CCS + Finished (encrypted) --- }
  ReadTLS12ChangeCipherSpec(FTransport);
  Rec := ReadTLSRecord(FTransport);
  if Rec.ContentType <> ctHandshake then
    raise ETLS12Error.CreateFmt(
      'TLS 1.2: expected handshake record after server CCS, got type %d',
      [Ord(Rec.ContentType)]);
  if not TLSAEADDecryptFragment(FAEADMode, FServerWriteKey,
    FServerWriteIV, QWord(0), Rec.ContentType, Rec.Version,
    Rec.Fragment, Plain) then
    raise ETLS12Error.Create(
      'TLS 1.2: failed to decrypt server Finished');
  Fin := DecodeTLSHandshakeMessage(Plain);
  if Fin.MsgType <> htFinished then
    raise ETLS12Error.Create(
      'TLS 1.2: server did not send Finished after CCS');
  ServerVD := ParseTLS12FinishedBody(Fin.Body);
  if not TLS12VerifyFinished(FHashKind, FMasterSecret,
    TLSFinishedLabelServer, FBuffer.Transcript, ServerVD) then
    raise ETLS12Error.Create(
      'TLS 1.2: server VerifyData mismatch');
  Inc(FServerSeq);

  FHandshakeDone := True;
end;

procedure TTLS12Client.Connect(ATransport: ITLSTransport);
begin
  if FHandshakeDone then
    raise ETLS12Error.Create('TLS 1.2: client already connected');
  if ATransport = nil then
    raise ETLS12Error.Create('TLS 1.2: transport is nil');
  FTransport := ATransport;
  FConnected := True;
  try
    DoHandshake;
  except
    FConnected := False;
    raise;
  end;
end;

procedure TTLS12Client.Send(const AData: TBytes);
var
  Offset, Total, Chunk: Integer;
  Part, Frag: TBytes;
begin
  if not FHandshakeDone then
    raise ETLS12Error.Create('TLS 1.2: Send before handshake complete');
  Total := Length(AData);
  if Total = 0 then
    Exit;
  Offset := 0;
  while Offset < Total do
  begin
    Chunk := Total - Offset;
    if Chunk > TLSRecordMaxPayload then
      Chunk := TLSRecordMaxPayload;
    SetLength(Part, Chunk);
    Move(AData[Offset], Part[0], Chunk);
    Frag := TLSAEADEncryptFragment(FAEADMode, FClientWriteKey,
      FClientWriteIV, FClientSeq, ctApplicationData, TLS12Version, Part);
    WriteTLSRecord(FTransport, ctApplicationData, Frag);
    Inc(FClientSeq);
    Inc(Offset, Chunk);
  end;
end;

function TTLS12Client.Recv(var ABuffer; ACount: LongInt): LongInt;
var
  Rec: TTLSRecord;
  Plain: TBytes;
  Alert: TTLSAlert;
  Avail, ToCopy: LongInt;
begin
  if not FHandshakeDone then
    raise ETLS12Error.Create('TLS 1.2: Recv before handshake complete');
  if ACount <= 0 then
    Exit(0);

  Result := 0;
  while True do
  begin
    { Return any buffered plaintext first. }
    Avail := Length(FRecvBuf) - FRecvPos;
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
      begin
        { Transport closed or error: signal EOF. }
        Exit(0);
      end;
    end;

    case Rec.ContentType of
      ctApplicationData:
        begin
          if not TLSAEADDecryptFragment(FAEADMode, FServerWriteKey,
            FServerWriteIV, FServerSeq, Rec.ContentType, Rec.Version,
            Rec.Fragment, Plain) then
            raise ETLS12Error.Create(
              'TLS 1.2: failed to decrypt server application data');
          Inc(FServerSeq);
          { Append to receive buffer. }
          if Length(FRecvBuf) = 0 then
          begin
            FRecvBuf := Plain;
            FRecvPos := 0;
          end
          else
          begin
            SetLength(FRecvBuf, Length(FRecvBuf) + Length(Plain));
            if Length(Plain) > 0 then
              Move(Plain[0], FRecvBuf[Length(FRecvBuf) - Length(Plain)],
                Length(Plain));
          end;
          { Return as much as requested. }
          Avail := Length(FRecvBuf) - FRecvPos;
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
      ctAlert:
        begin
          {After the handshake alerts are protected like application data
            (RFC 5246, 6.2.3), so decrypt before decoding.}
          if not TLSAEADDecryptFragment(FAEADMode, FServerWriteKey,
            FServerWriteIV, FServerSeq, Rec.ContentType, Rec.Version,
            Rec.Fragment, Plain) then
            raise ETLS12Error.Create(
              'TLS 1.2: failed to decrypt server alert');
          Inc(FServerSeq);
          Alert := DecodeTLSAlert(Plain);
          if Alert.Description = adCloseNotify then
            Exit(0);  { Normal closure. }
          if TLS12AlertIsFatal(Alert) then
            raise ETLS12Error.CreateFmt(
              'TLS 1.2: fatal alert from server: %s',
              [TLSAlertDescriptionName(Alert.Description)]);
          { Non-fatal warning: continue reading. }
          Continue;
        end;
      ctChangeCipherSpec:
        begin
          raise ETLS12Error.Create(
            'TLS 1.2: unexpected ChangeCipherSpec after handshake');
        end;
      ctHandshake:
        begin
          raise ETLS12Error.Create(
            'TLS 1.2: unexpected handshake message after handshake');
        end;
    else
      raise ETLS12Error.CreateFmt(
        'TLS 1.2: unexpected record type %d after handshake',
        [Ord(Rec.ContentType)]);
    end;
  end;
end;

procedure TTLS12Client.Shutdown;
begin
  if not FConnected then
    Exit;
  if FHandshakeDone then
    WriteTLS12Alert(FTransport, alWarning, adCloseNotify);
  FConnected := False;
  FHandshakeDone := False;
end;

procedure TTLS12Client.Close;
begin
  FConnected := False;
  FHandshakeDone := False;
end;


end.
