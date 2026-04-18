unit CryptoKit.Interfaces;

interface

uses
  System.SysUtils,
  CryptoKit.Types;

type
  ICryptoHashService = interface
    ['{1E829D38-4B35-4F7F-AFE5-A4642B2B93A9}']
    function Hash(
      const AData: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm = haSHA256
    ): TBytes;
    function Hmac(
      const AData, AKey: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm = haSHA256
    ): TBytes;
  end;

  ICryptoKdfService = interface
    ['{44DC7842-2E9D-4F22-B735-00A8DA6FCA2A}']
    function DeriveKey(
      const APassword, ASalt: TBytes;
      const AIterations, AKeyLength: Integer;
      const AAlgorithm: TCryptoKdfAlgorithm = kdfPBKDF2_HMAC_SHA256
    ): TBytes;
  end;

  ICryptoCipherService = interface
    ['{D3CFD9B7-58DF-4A86-829C-9BCEB98A47D8}']
    function Encrypt(
      const APlainData: TBytes;
      const AParams: TCryptoAesParams;
      const AAlgorithm: TCryptoCipherAlgorithm = caAES256_CBC_PKCS7
    ): TBytes;
    function Decrypt(
      const ACipherData: TBytes;
      const AParams: TCryptoAesParams;
      const AAlgorithm: TCryptoCipherAlgorithm = caAES256_CBC_PKCS7
    ): TBytes;
  end;

  ICryptoRandomService = interface
    ['{CB751E7D-F462-4F0A-918A-764F53A035F9}']
    function GetBytes(const ACount: Integer): TBytes;
  end;

implementation

end.
