unit CryptoKit.WinApiCryptService;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoWinApiCryptService = class(TCryptoServiceBase, ICryptoService)
  private
    FCertificateService: ICryptoCertificateService;
    FSignatureService: ICryptoSignatureService;
    function ResolveStoreFlag(const AStoreLocation: TCertificateStoreLocation): DWORD;
    function OpenStore(
      const AStoreName: string;
      const AStoreLocation: TCertificateStoreLocation
    ): HCERTSTORE;
  public
    constructor Create(
      const ACertificateService: ICryptoCertificateService = nil;
      const ASignatureService: ICryptoSignatureService = nil
    );
    function Sign(
      const AContent, ACertificateEncoded: TBytes
    ): TBytes;
    function VerifySignature(
      const AContent, ASignature: TBytes
    ): TCryptoBytesArray;
    function Decrypt(
      const AEncryptedContent: TBytes;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TBytes;
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
  CryptoKit.CertificateService,
  CryptoKit.SignatureService,
  CryptoKit.Utils;

constructor TCryptoWinApiCryptService.Create(
  const ACertificateService: ICryptoCertificateService;
  const ASignatureService: ICryptoSignatureService
);
begin
  inherited Create;
  if Assigned(ACertificateService) then
    FCertificateService := ACertificateService
  else
    FCertificateService := TCryptoCertificateService.Create;

  if Assigned(ASignatureService) then
    FSignatureService := ASignatureService
  else
    FSignatureService := TCryptoSignatureService.Create;
end;

function TCryptoWinApiCryptService.ResolveStoreFlag(
  const AStoreLocation: TCertificateStoreLocation
): DWORD;
begin
  case AStoreLocation of
    slCurrentUser: Result := CERT_SYSTEM_STORE_CURRENT_USER;
    slLocalMachine: Result := CERT_SYSTEM_STORE_LOCAL_MACHINE;
  else
    raise ECryptoValidationError.Create('Unsupported certificate store location');
  end;
end;

function TCryptoWinApiCryptService.OpenStore(
  const AStoreName: string;
  const AStoreLocation: TCertificateStoreLocation
): HCERTSTORE;
begin
  Result := CertOpenStore(
    Pointer(CERT_STORE_PROV_SYSTEM),
    0,
    0,
    ResolveStoreFlag(AStoreLocation) or CERT_STORE_READONLY_FLAG or CERT_STORE_OPEN_EXISTING_FLAG,
    PWideChar(AStoreName)
  );
  if Result = nil then
    RaiseLastOSError;
end;

function TCryptoWinApiCryptService.Sign(
  const AContent, ACertificateEncoded: TBytes
): TBytes;
begin
  Result := FSignatureService.SignDetached(AContent, ACertificateEncoded);
end;

function TCryptoWinApiCryptService.VerifySignature(
  const AContent, ASignature: TBytes
): TCryptoBytesArray;
var
  Signers: TCryptoCertificateArray;
  Signer: TCryptoCertificate;
  Items: TList<TBytes>;
begin
  Signers := FSignatureService.VerifyDetached(AContent, ASignature);
  Items := TList<TBytes>.Create;
  try
    for Signer in Signers do
      Items.Add(CloneBytes(Signer.Encoded));
    Result := Items.ToArray;
  finally
    Items.Free;
  end;
end;

function TCryptoWinApiCryptService.Decrypt(
  const AEncryptedContent: TBytes;
  const AStoreLocation: TCertificateStoreLocation
): TBytes;
var
  StoreHandle: HCERTSTORE;
  StoreHandleArray: array[0..0] of HCERTSTORE;
  DecryptParams: CRYPT_DECRYPT_MESSAGE_PARA;
  OutputLen: DWORD;
begin
  RequireNotEmpty(AEncryptedContent, 'Encrypted content');
  StoreHandle := OpenStore(CERT_STORE_NAME_MY, AStoreLocation);
  try
    FillChar(DecryptParams, SizeOf(DecryptParams), 0);
    StoreHandleArray[0] := StoreHandle;
    DecryptParams.cbSize := SizeOf(DecryptParams);
    DecryptParams.dwMsgAndCertEncodingType := ENCODING;
    DecryptParams.cCertStore := 1;
    DecryptParams.rghCertStore := @StoreHandleArray[0];

    OutputLen := 0;
    if not CryptDecryptMessage(
      DecryptParams,
      BytesPtr(AEncryptedContent),
      Length(AEncryptedContent),
      nil,
      OutputLen,
      nil
    ) then
      RaiseLastOSError;

    SetLength(Result, OutputLen);
    if not CryptDecryptMessage(
      DecryptParams,
      BytesPtr(AEncryptedContent),
      Length(AEncryptedContent),
      BytesPtr(Result),
      OutputLen,
      nil
    ) then
      RaiseLastOSError;
    SetLength(Result, OutputLen);
  finally
    CertCloseStore(StoreHandle, 0);
  end;
end;

function TCryptoWinApiCryptService.GetPersonalCertificates(
  const AOnlyWithPrivateKey: Boolean;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificateArray;
begin
  Result := FCertificateService.GetPersonalCertificates(
    AOnlyWithPrivateKey,
    AStoreLocation
  );
end;

function TCryptoWinApiCryptService.GetCertificateWithPrivateKeyByThumbprint(
  const AThumbprintHex: string;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificate;
begin
  Result := FCertificateService.GetCertificateWithPrivateKeyByThumbprint(
    AThumbprintHex,
    AStoreLocation
  );
end;

end.
