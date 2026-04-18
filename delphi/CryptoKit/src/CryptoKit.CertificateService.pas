unit CryptoKit.CertificateService;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoCertificateService = class(TCryptoServiceBase, ICryptoCertificateService)
  private
    function ResolveStoreFlag(const AStoreLocation: TCertificateStoreLocation): DWORD;
    function OpenPersonalStore(const AStoreLocation: TCertificateStoreLocation): Pointer;
    function HasPrivateKey(const ACertContext: PCERT_CONTEXT): Boolean;
    function ReadCertificateHashHex(const ACertContext: PCERT_CONTEXT): string;
    function ReadCertificateEncoded(const ACertContext: PCERT_CONTEXT): TBytes;
    function BuildCertificateInfo(
      const ACertContext: PCERT_CONTEXT;
      const AHasPrivateKey: Boolean
    ): TCryptoCertificate;
  public
    function GetPersonalCertificates(
      const AOnlyWithPrivateKey: Boolean;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TCryptoCertificateArray;
    function GetCertificateWithPrivateKeyByThumbprint(
      const AThumbprintHex: string;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TCryptoCertificate;
  end;

implementation

uses
  CryptoKit.CryptApi,
  CryptoKit.Exceptions,
  CryptoKit.Encoding,
  CryptoKit.Utils;

function NormalizeThumbprint(const AThumbprintHex: string): string;
begin
  Result := LowerCase(StringReplace(AThumbprintHex, ' ', '', [rfReplaceAll]));
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

function TCryptoCertificateService.ResolveStoreFlag(
  const AStoreLocation: TCertificateStoreLocation
): DWORD;
begin
  case AStoreLocation of
    slCurrentUser: Result := CERT_SYSTEM_STORE_CURRENT_USER;
    slLocalMachine: Result := CERT_SYSTEM_STORE_LOCAL_MACHINE;
  else
    raise ECryptoAlgorithmError.Create('Unsupported certificate store location');
  end;
end;

function TCryptoCertificateService.OpenPersonalStore(
  const AStoreLocation: TCertificateStoreLocation
): Pointer;
begin
  Result := CertOpenStore(
    Pointer(CERT_STORE_PROV_SYSTEM),
    0,
    0,
    ResolveStoreFlag(AStoreLocation) or
      CERT_STORE_OPEN_EXISTING_FLAG or
      CERT_STORE_READONLY_FLAG,
    PWideChar(CERT_STORE_NAME_MY)
  );
  if Result = nil then
    RaiseLastOSError;
end;

function TCryptoCertificateService.HasPrivateKey(
  const ACertContext: PCERT_CONTEXT
): Boolean;
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

function TCryptoCertificateService.ReadCertificateHashHex(
  const ACertContext: PCERT_CONTEXT
): string;
var
  DataLen: DWORD;
  HashBytes: TBytes;
begin
  DataLen := 0;
  if not CertGetCertificateContextProperty(
    ACertContext,
    CERT_HASH_PROP_ID,
    nil,
    DataLen
  ) then
    RaiseLastOSError;

  SetLength(HashBytes, DataLen);
  if not CertGetCertificateContextProperty(
    ACertContext,
    CERT_HASH_PROP_ID,
    @HashBytes[0],
    DataLen
  ) then
    RaiseLastOSError;

  Result := BytesToHex(HashBytes);
end;

function TCryptoCertificateService.ReadCertificateEncoded(
  const ACertContext: PCERT_CONTEXT
): TBytes;
begin
  SetLength(Result, ACertContext.cbCertEncoded);
  if ACertContext.cbCertEncoded > 0 then
    Move(ACertContext.pbCertEncoded^, Result[0], ACertContext.cbCertEncoded);
end;

function TCryptoCertificateService.BuildCertificateInfo(
  const ACertContext: PCERT_CONTEXT;
  const AHasPrivateKey: Boolean
): TCryptoCertificate;
begin
  Result.ThumbprintHex := NormalizeThumbprint(ReadCertificateHashHex(ACertContext));
  Result.HasPrivateKey := AHasPrivateKey;
  Result.Encoded := ReadCertificateEncoded(ACertContext);
  Result.SubjectName := GetCertificateName(ACertContext, False);
  Result.IssuerName := GetCertificateName(ACertContext, True);
end;

function TCryptoCertificateService.GetPersonalCertificates(
  const AOnlyWithPrivateKey: Boolean;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificateArray;
var
  StoreHandle: Pointer;
  CertContext: PCERT_CONTEXT;
  HasKey: Boolean;
  Items: TList<TCryptoCertificate>;
begin
  StoreHandle := OpenPersonalStore(AStoreLocation);
  Items := TList<TCryptoCertificate>.Create;
  try
    CertContext := nil;
    while True do
    begin
      CertContext := CertEnumCertificatesInStore(StoreHandle, CertContext);
      if CertContext = nil then
      begin
        if GetLastError <> ERROR_NO_MORE_FILES then
          RaiseLastOSError;
        Break;
      end;

      HasKey := HasPrivateKey(CertContext);
      if (not AOnlyWithPrivateKey) or HasKey then
        Items.Add(BuildCertificateInfo(CertContext, HasKey));
    end;
    Result := Items.ToArray;
  finally
    Items.Free;
    CertCloseStore(StoreHandle, 0);
  end;
end;

function TCryptoCertificateService.GetCertificateWithPrivateKeyByThumbprint(
  const AThumbprintHex: string;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificate;
var
  NormalizedThumbprint: string;
  Certificates: TCryptoCertificateArray;
  Cert: TCryptoCertificate;
begin
  RequireTrue(Trim(AThumbprintHex) <> '', 'Certificate thumbprint must not be empty');

  NormalizedThumbprint := NormalizeThumbprint(AThumbprintHex);
  Certificates := GetPersonalCertificates(True, AStoreLocation);
  for Cert in Certificates do
  begin
    if NormalizeThumbprint(Cert.ThumbprintHex) = NormalizedThumbprint then
      Exit(Cert);
  end;

  raise ECryptoValidationError.Create('Certificate with private key not found by thumbprint');
end;

end.
