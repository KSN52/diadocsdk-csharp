unit CryptoKit.Facade;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.Interfaces;

type
  TCryptoKit = class
  private
    class var FHashService: ICryptoHashService;
    class var FKdfService: ICryptoKdfService;
    class var FCipherService: ICryptoCipherService;
    class var FRandomService: ICryptoRandomService;
    class function HashService: ICryptoHashService; static;
    class function KdfService: ICryptoKdfService; static;
    class function CipherService: ICryptoCipherService; static;
    class function RandomService: ICryptoRandomService; static;
  public
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
  end;

implementation

uses
  CryptoKit.Factory;

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

end.
