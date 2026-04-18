unit CryptoKit.Facade;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.Interfaces;

type
  TCryptoKit = class
  private
    class var FCryptoService: ICryptoService;
    class var FHashService: ICryptoHashService;
    class var FKdfService: ICryptoKdfService;
    class var FCipherService: ICryptoCipherService;
    class var FRandomService: ICryptoRandomService;
    class var FCertificateService: ICryptoCertificateService;
    class var FSignatureService: ICryptoSignatureService;
    class function CryptoService: ICryptoService; static;
    class function HashService: ICryptoHashService; static;
    class function KdfService: ICryptoKdfService; static;
    class function CipherService: ICryptoCipherService; static;
    class function RandomService: ICryptoRandomService; static;
    class function CertificateService: ICryptoCertificateService; static;
    class function SignatureService: ICryptoSignatureService; static;
  public
    class function CreateExtendedWinApiCryptService(
      const ACertificateEncoded: TBytes
    ): IExtendedWinApiCryptService; static;

    class function Sign(
      const AContent, ACertificateEncoded: TBytes
    ): TBytes; static;

    class function VerifySignature(
      const AContent, ASignature: TBytes
    ): TCryptoBytesArray; static;

    class function Decrypt(
      const AEncryptedContent: TBytes;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TBytes; static;

    class function Hash(
      const AData: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm = haSHA256
    ): TBytes; static;

    class function Hmac(
      const AData, AKey: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm = haSHA256
    ): TBytes; static;

    class function DeriveKey(
      const APassword, ASalt: TBytes;
      const AIterations, AKeyLength: Integer;
      const AAlgorithm: TCryptoKdfAlgorithm = kdfPBKDF2_HMAC_SHA256
    ): TBytes; static;

    class function EncryptAes256Cbc(
      const APlainData, AKey, AIV: TBytes
    ): TBytes; static;

    class function DecryptAes256Cbc(
      const ACipherData, AKey, AIV: TBytes
    ): TBytes; static;

    class function RandomBytes(const ACount: Integer): TBytes; static;

    class function GetPersonalCertificates(
      const AOnlyWithPrivateKey: Boolean;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TCryptoCertificateArray; static;

    class function GetCertificateWithPrivateKeyByThumbprint(
      const AThumbprintHex: string;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TCryptoCertificate; static;

    class function SignDetached(
      const AContent, ACertificateEncoded: TBytes
    ): TBytes; static;

    class function VerifyDetached(
      const AContent, ADetachedSignature: TBytes
    ): TCryptoCertificateArray; static;
  end;

implementation

uses
  CryptoKit.Factory,
  CryptoKit.ExtendedWinApiCryptService;

class function TCryptoKit.CryptoService: ICryptoService;
begin
  if not Assigned(FCryptoService) then
    FCryptoService := TCryptoFactory.CreateCryptoService;
  Result := FCryptoService;
end;

class function TCryptoKit.HashService: ICryptoHashService;
begin
  if not Assigned(FHashService) then
    FHashService := TCryptoFactory.CreateHashService;
  Result := FHashService;
end;

class function TCryptoKit.KdfService: ICryptoKdfService;
begin
  if not Assigned(FKdfService) then
    FKdfService := TCryptoFactory.CreateKdfService;
  Result := FKdfService;
end;

class function TCryptoKit.CipherService: ICryptoCipherService;
begin
  if not Assigned(FCipherService) then
    FCipherService := TCryptoFactory.CreateCipherService;
  Result := FCipherService;
end;

class function TCryptoKit.RandomService: ICryptoRandomService;
begin
  if not Assigned(FRandomService) then
    FRandomService := TCryptoFactory.CreateRandomService;
  Result := FRandomService;
end;

class function TCryptoKit.CertificateService: ICryptoCertificateService;
begin
  if not Assigned(FCertificateService) then
    FCertificateService := TCryptoFactory.CreateCertificateService;
  Result := FCertificateService;
end;

class function TCryptoKit.SignatureService: ICryptoSignatureService;
begin
  if not Assigned(FSignatureService) then
    FSignatureService := TCryptoFactory.CreateSignatureService;
  Result := FSignatureService;
end;

class function TCryptoKit.Sign(
  const AContent, ACertificateEncoded: TBytes
): TBytes;
begin
  Result := CryptoService.Sign(AContent, ACertificateEncoded);
end;

class function TCryptoKit.VerifySignature(
  const AContent, ASignature: TBytes
): TCryptoBytesArray;
begin
  Result := CryptoService.VerifySignature(AContent, ASignature);
end;

class function TCryptoKit.Decrypt(
  const AEncryptedContent: TBytes;
  const AStoreLocation: TCertificateStoreLocation
): TBytes;
begin
  Result := CryptoService.Decrypt(AEncryptedContent, AStoreLocation);
end;

class function TCryptoKit.Hash(
  const AData: TBytes;
  const AAlgorithm: TCryptoHashAlgorithm
): TBytes;
begin
  Result := HashService.Hash(AData, AAlgorithm);
end;

class function TCryptoKit.Hmac(
  const AData, AKey: TBytes;
  const AAlgorithm: TCryptoHashAlgorithm
): TBytes;
begin
  Result := HashService.Hmac(AData, AKey, AAlgorithm);
end;

class function TCryptoKit.DeriveKey(
  const APassword, ASalt: TBytes;
  const AIterations, AKeyLength: Integer;
  const AAlgorithm: TCryptoKdfAlgorithm
): TBytes;
begin
  Result := KdfService.DeriveKey(APassword, ASalt, AIterations, AKeyLength, AAlgorithm);
end;

class function TCryptoKit.EncryptAes256Cbc(
  const APlainData, AKey, AIV: TBytes
): TBytes;
begin
  Result := CipherService.Encrypt(APlainData, TCryptoAesParams.Create(AKey, AIV), caAES256_CBC_PKCS7);
end;

class function TCryptoKit.DecryptAes256Cbc(
  const ACipherData, AKey, AIV: TBytes
): TBytes;
begin
  Result := CipherService.Decrypt(ACipherData, TCryptoAesParams.Create(AKey, AIV), caAES256_CBC_PKCS7);
end;

class function TCryptoKit.RandomBytes(const ACount: Integer): TBytes;
begin
  Result := RandomService.GetBytes(ACount);
end;

class function TCryptoKit.GetPersonalCertificates(
  const AOnlyWithPrivateKey: Boolean;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificateArray;
begin
  Result := CertificateService.GetPersonalCertificates(AOnlyWithPrivateKey, AStoreLocation);
end;

class function TCryptoKit.GetCertificateWithPrivateKeyByThumbprint(
  const AThumbprintHex: string;
  const AStoreLocation: TCertificateStoreLocation
): TCryptoCertificate;
begin
  Result := CertificateService.GetCertificateWithPrivateKeyByThumbprint(
    AThumbprintHex,
    AStoreLocation
  );
end;

class function TCryptoKit.SignDetached(
  const AContent, ACertificateEncoded: TBytes
): TBytes;
begin
  Result := SignatureService.SignDetached(AContent, ACertificateEncoded);
end;

class function TCryptoKit.VerifyDetached(
  const AContent, ADetachedSignature: TBytes
): TCryptoCertificateArray;
begin
  Result := SignatureService.VerifyDetached(AContent, ADetachedSignature);
end;

class function TCryptoKit.CreateExtendedWinApiCryptService(
  const ACertificateEncoded: TBytes
): IExtendedWinApiCryptService;
begin
  Result := TCryptoFactory.CreateExtendedWinApiCryptService(ACertificateEncoded);
end;

end.
