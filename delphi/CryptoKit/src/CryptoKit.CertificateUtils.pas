unit CryptoKit.CertificateUtils;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.CryptApi;

function NormalizeThumbprint(const AThumbprintHex: string): string;
function IsGostSignatureOid(const AOid: string): Boolean;
function ResolveHashOidBySignatureOid(const ASignatureOid: string): AnsiString;
function GetCertificateSignatureAlgorithmOid(
  const ACertContext: PCERT_CONTEXT
): string;
function GetCertificatePublicKeyAlgorithmOid(
  const ACertContext: PCERT_CONTEXT
): string;
function GetCertificateName(
  const ACertContext: PCERT_CONTEXT;
  const AIsIssuer: Boolean
): string;
function ReadCertificateHash(const ACertContext: PCERT_CONTEXT): TBytes;
function ReadCertificateHashHex(const ACertContext: PCERT_CONTEXT): string;
function ReadCertificateEncoded(const ACertContext: PCERT_CONTEXT): TBytes;
function HasPrivateKey(const ACertContext: PCERT_CONTEXT): Boolean;
function BuildCertificateInfo(
  const ACertContext: PCERT_CONTEXT;
  const AHasPrivateKey: Boolean
): TCryptoCertificate;

implementation

uses
  Winapi.Windows,
  Winapi.WinCrypt,
  CryptoKit.Encoding;

function NormalizeThumbprint(const AThumbprintHex: string): string;
begin
  Result := LowerCase(StringReplace(AThumbprintHex, ' ', '', [rfReplaceAll]));
end;

function IsGostSignatureOid(const AOid: string): Boolean;
begin
  Result :=
    (AOid = OID_GOST_34_11_94_R3410EL) or
    (AOid = OID_GOST_34_11_12_256_R3410) or
    (AOid = OID_GOST_34_11_12_512_R3410);
end;

function ResolveHashOidBySignatureOid(const ASignatureOid: string): AnsiString;
begin
  if ASignatureOid = OID_GOST_34_11_94_R3410EL then
    Exit(AnsiString(OID_GOST_34_11_94));
  if ASignatureOid = OID_GOST_34_11_12_256_R3410 then
    Exit(AnsiString(OID_GOST_34_11_12_256));
  if ASignatureOid = OID_GOST_34_11_12_512_R3410 then
    Exit(AnsiString(OID_GOST_34_11_12_512));
  Result := AnsiString('2.16.840.1.101.3.4.2.1');
end;

function GetCertificateSignatureAlgorithmOid(
  const ACertContext: PCERT_CONTEXT
): string;
var
  CertInfo: PCERT_INFO;
begin
  CertInfo := PCERT_INFO(ACertContext.pCertInfo);
  Result := string(AnsiString(CertInfo^.SignatureAlgorithm.pszObjId));
end;

function GetCertificatePublicKeyAlgorithmOid(
  const ACertContext: PCERT_CONTEXT
): string;
var
  CertInfo: PCERT_INFO;
begin
  CertInfo := PCERT_INFO(ACertContext.pCertInfo);
  Result := string(AnsiString(CertInfo^.SubjectPublicKeyInfo.Algorithm.pszObjId));
end;

function GetCertificateName(
  const ACertContext: PCERT_CONTEXT;
  const AIsIssuer: Boolean
): string;
var
  NameFlags: DWORD;
  NameLen: DWORD;
begin
  if AIsIssuer then
    NameFlags := CERT_NAME_ISSUER_FLAG
  else
    NameFlags := 0;

  NameLen := CertGetNameStringW(
    ACertContext,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
    NameFlags,
    nil,
    nil,
    0
  );
  if NameLen <= 1 then
    Exit('');

  SetLength(Result, NameLen - 1);
  CertGetNameStringW(
    ACertContext,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
    NameFlags,
    nil,
    PWideChar(Result),
    NameLen
  );
end;

function ReadCertificateHash(const ACertContext: PCERT_CONTEXT): TBytes;
var
  DataLen: DWORD;
begin
  DataLen := 0;
  if not CertGetCertificateContextProperty(
    ACertContext,
    CERT_HASH_PROP_ID,
    nil,
    DataLen
  ) then
    RaiseLastOSError;

  SetLength(Result, DataLen);
  if not CertGetCertificateContextProperty(
    ACertContext,
    CERT_HASH_PROP_ID,
    @Result[0],
    DataLen
  ) then
    RaiseLastOSError;
end;

function ReadCertificateHashHex(const ACertContext: PCERT_CONTEXT): string;
begin
  Result := NormalizeThumbprint(BytesToHex(ReadCertificateHash(ACertContext)));
end;

function ReadCertificateEncoded(const ACertContext: PCERT_CONTEXT): TBytes;
begin
  SetLength(Result, ACertContext.cbCertEncoded);
  if ACertContext.cbCertEncoded > 0 then
    Move(ACertContext.pbCertEncoded^, Result[0], ACertContext.cbCertEncoded);
end;

function HasPrivateKey(const ACertContext: PCERT_CONTEXT): Boolean;
var
  DataLen: DWORD;
  LastErr: DWORD;
begin
  DataLen := 0;
  Result := CertGetCertificateContextProperty(
    ACertContext,
    CERT_KEY_PROV_INFO_PROP_ID,
    nil,
    DataLen
  );
  if Result then
    Exit(True);

  LastErr := GetLastError;
  if LastErr = DWORD(CRYPT_E_NOT_FOUND) then
    Exit(False);
  RaiseLastOSError(LastErr);
end;

function BuildCertificateInfo(
  const ACertContext: PCERT_CONTEXT;
  const AHasPrivateKey: Boolean
): TCryptoCertificate;
begin
  Result.ThumbprintHex := ReadCertificateHashHex(ACertContext);
  Result.SubjectName := GetCertificateName(ACertContext, False);
  Result.IssuerName := GetCertificateName(ACertContext, True);
  Result.SignatureAlgorithmOid := GetCertificateSignatureAlgorithmOid(ACertContext);
  Result.PublicKeyAlgorithmOid := GetCertificatePublicKeyAlgorithmOid(ACertContext);
  Result.IsGost := IsGostSignatureOid(Result.SignatureAlgorithmOid);
  Result.HasPrivateKey := AHasPrivateKey;
  Result.Encoded := ReadCertificateEncoded(ACertContext);
end;

end.
