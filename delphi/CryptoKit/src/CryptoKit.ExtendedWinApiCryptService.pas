unit CryptoKit.ExtendedWinApiCryptService;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoExtendedWinApiCryptService = class(TCryptoServiceBase, IExtendedWinApiCryptService)
  private
    FInnerService: ICryptoService;
    FSigningCertificateEncoded: TBytes;
  public
    constructor Create(
      const ACertificateEncoded: TBytes;
      const AInnerService: ICryptoService = nil
    );
    function Sign(const AContent: TBytes): TBytes; overload;
    function Sign(
      const AContent, ACertificateEncoded: TBytes
    ): TBytes; overload;
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
  CryptoKit.WinApiCryptService,
  CryptoKit.Utils;

constructor TCryptoExtendedWinApiCryptService.Create(
  const ACertificateEncoded: TBytes;
  const AInnerService: ICryptoService
);
begin
  inherited Create;
  RequireNotEmpty(ACertificateEncoded, 'Signing certificate');
  FSigningCertificateEncoded := CloneBytes(ACertificateEncoded);

  if Assigned(AInnerService) then
    FInnerService := AInnerService
  else
    FInnerService := TCryptoWinApiCryptService.Create;
end;

function TCryptoExtendedWinApiCryptService.Sign(const AContent: TBytes): TBytes;
begin
  Result := FInnerService.Sign(AContent, FSigningCertificateEncoded);
end;

function TCryptoExtendedWinApiCryptService.Sign(
  const AContent, ACertificateEncoded: TBytes
): TBytes;
begin
  Result := FInnerService.Sign(AContent, ACertificateEncoded);
end;

function TCryptoExtendedWinApiCryptService.VerifySignature(
  const AContent, ASignature: TBytes
): TCryptoBytesArray;
begin
  Result := FInnerService.VerifySignature(AContent, ASignature);
end;

function TCryptoExtendedWinApiCryptService.Decrypt(
  const AEncryptedContent: TBytes;
  const AStoreLocation: TCertificateStoreLocation
): TBytes;
begin
  Result := FInnerService.Decrypt(AEncryptedContent, AStoreLocation);
end;

function TCryptoExtendedWinApiCryptService.GetPersonalCertificates(
  const AOnlyWithPrivateKey: Boolean;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificateArray;
begin
  Result := FInnerService.GetPersonalCertificates(AOnlyWithPrivateKey, AStoreLocation);
end;

function TCryptoExtendedWinApiCryptService.GetCertificateWithPrivateKeyByThumbprint(
  const AThumbprintHex: string;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificate;
begin
  Result := FInnerService.GetCertificateWithPrivateKeyByThumbprint(
    AThumbprintHex,
    AStoreLocation
  );
end;

end.
