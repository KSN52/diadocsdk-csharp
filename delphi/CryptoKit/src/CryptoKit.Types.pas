unit CryptoKit.Types;

interface

uses
  System.SysUtils;

type
  TCryptoHashAlgorithm = (haSHA256, haSHA512);

  TCryptoKdfAlgorithm = (kdfPBKDF2_HMAC_SHA256);

  TCryptoCipherAlgorithm = (caAES256_CBC_PKCS7);

  TCertificateStoreLocation = (slCurrentUser, slLocalMachine);

  TCryptoCertificate = record
    ThumbprintHex: string;
    SubjectName: string;
    IssuerName: string;
    SignatureAlgorithmOid: string;
    PublicKeyAlgorithmOid: string;
    IsGost: Boolean;
    HasPrivateKey: Boolean;
    Encoded: TBytes;
  end;

  TCryptoCertificateArray = TArray<TCryptoCertificate>;
  TCryptoBytesArray = TArray<TBytes>;

  TCryptoAesParams = record
    Key: TBytes;
    IV: TBytes;
    class function Create(const AKey, AIV: TBytes): TCryptoAesParams; static;
  end;

function CloneBytes(const AData: TBytes): TBytes;

implementation

class function TCryptoAesParams.Create(const AKey, AIV: TBytes): TCryptoAesParams;
begin
  Result.Key := CloneBytes(AKey);
  Result.IV := CloneBytes(AIV);
end;

function CloneBytes(const AData: TBytes): TBytes;
begin
  Result := System.Copy(AData, 0, Length(AData));
end;

end.
