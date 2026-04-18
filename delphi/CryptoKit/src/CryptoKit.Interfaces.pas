unit CryptoKit.Interfaces;

interface

uses
  System.SysUtils,
  CryptoKit.Types;

type
  ICryptoService = interface
    ['{934245E7-A87A-4E69-A7DF-0D35598C43B5}']
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

  IExtendedWinApiCryptService = interface(ICryptoService)
    ['{7EF29B4B-14C7-44C0-BF7B-4A57FEEE3C82}']
    function Sign(const AContent: TBytes): TBytes; overload;
  end;

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

  ICryptoCertificateService = interface
    ['{9117111C-EF94-4D42-9FC0-4CBC8CB0E996}']
    function GetPersonalCertificates(
      const AOnlyWithPrivateKey: Boolean;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TCryptoCertificateArray;
    function GetCertificateWithPrivateKeyByThumbprint(
      const AThumbprintHex: string;
      const AStoreLocation: TCertificateStoreLocation = slCurrentUser
    ): TCryptoCertificate;
  end;

  ICryptoSignatureService = interface
    ['{81140B8C-5D26-4D09-968D-4D4AC6CA8CF3}']
    function SignDetached(
      const AContent, ACertificateEncoded: TBytes
    ): TBytes;
    function VerifyDetached(
      const AContent, ADetachedSignature: TBytes
    ): TCryptoCertificateArray;
  end;

implementation

end.
