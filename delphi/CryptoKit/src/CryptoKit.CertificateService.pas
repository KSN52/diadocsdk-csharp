unit CryptoKit.CertificateService;

interface

uses
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
  System.SysUtils,
  CryptoKit.CryptApi,
  CryptoKit.CertificateUtils,
  CryptoKit.Exceptions,
  CryptoKit.Utils;

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
begin
  Result := CryptoKit.CertificateUtils.HasPrivateKey(ACertContext);
end;

function TCryptoCertificateService.ReadCertificateHashHex(
  const ACertContext: PCERT_CONTEXT
): string;
begin
  Result := CryptoKit.CertificateUtils.ReadCertificateHashHex(ACertContext);
end;

function TCryptoCertificateService.ReadCertificateEncoded(
  const ACertContext: PCERT_CONTEXT
): TBytes;
begin
  Result := CryptoKit.CertificateUtils.ReadCertificateEncoded(ACertContext);
end;

function TCryptoCertificateService.BuildCertificateInfo(
  const ACertContext: PCERT_CONTEXT;
  const AHasPrivateKey: Boolean
): TCryptoCertificate;
begin
  Result := CryptoKit.CertificateUtils.BuildCertificateInfo(ACertContext, AHasPrivateKey);
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
