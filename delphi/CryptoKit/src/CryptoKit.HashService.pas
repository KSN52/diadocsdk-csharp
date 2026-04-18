unit CryptoKit.HashService;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoHashService = class(TCryptoServiceBase, ICryptoHashService)
  private
    function ResolveAlgorithmName(const AAlgorithm: TCryptoHashAlgorithm): PWideChar;
    function ComputeHash(
      const AData, ASecret: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm;
      const AUseHmac: Boolean
    ): TBytes;
  public
    function Hash(
      const AData: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm = haSHA256
    ): TBytes;
    function Hmac(
      const AData, AKey: TBytes;
      const AAlgorithm: TCryptoHashAlgorithm = haSHA256
    ): TBytes;
  end;

implementation

uses
  Winapi.Windows,
  CryptoKit.BCryptApi,
  CryptoKit.BCryptHelpers,
  CryptoKit.Exceptions,
  CryptoKit.Utils;

function TCryptoHashService.ResolveAlgorithmName(
  const AAlgorithm: TCryptoHashAlgorithm
): PWideChar;
begin
  case AAlgorithm of
    haSHA256: Result := BCRYPT_SHA256_ALGORITHM;
    haSHA512: Result := BCRYPT_SHA512_ALGORITHM;
  else
    raise ECryptoAlgorithmError.Create('Unsupported hash algorithm');
  end;
end;

function TCryptoHashService.ComputeHash(
  const AData, ASecret: TBytes;
  const AAlgorithm: TCryptoHashAlgorithm;
  const AUseHmac: Boolean
): TBytes;
var
  AlgHandle: BCRYPT_ALG_HANDLE;
  HashHandle: BCRYPT_HASH_HANDLE;
  Flags: ULONG;
  ObjectLength: Cardinal;
  HashLength: Cardinal;
  HashObject: TBytes;
begin
  AlgHandle := nil;
  HashHandle := nil;
  Flags := 0;
  if AUseHmac then
    Flags := BCRYPT_ALG_HANDLE_HMAC_FLAG;

  CheckNtStatus(
    BCryptOpenAlgorithmProvider(
      @AlgHandle,
      ResolveAlgorithmName(AAlgorithm),
      nil,
      Flags
    ),
    'BCryptOpenAlgorithmProvider'
  );
  try
    ObjectLength := ReadAlgorithmDwordProperty(AlgHandle, BCRYPT_OBJECT_LENGTH);
    HashLength := ReadAlgorithmDwordProperty(AlgHandle, BCRYPT_HASH_LENGTH);
    SetLength(HashObject, ObjectLength);
    SetLength(Result, HashLength);

    CheckNtStatus(
      BCryptCreateHash(
        AlgHandle,
        @HashHandle,
        BytesPtr(HashObject),
        Length(HashObject),
        BytesPtr(ASecret),
        Length(ASecret),
        0
      ),
      'BCryptCreateHash'
    );
    try
      if Length(AData) > 0 then
        CheckNtStatus(
          BCryptHashData(HashHandle, BytesPtr(AData), Length(AData), 0),
          'BCryptHashData'
        );

      CheckNtStatus(
        BCryptFinishHash(HashHandle, BytesPtr(Result), Length(Result), 0),
        'BCryptFinishHash'
      );
    finally
      BCryptDestroyHash(HashHandle);
    end;
  finally
    BCryptCloseAlgorithmProvider(AlgHandle, 0);
  end;
end;

function TCryptoHashService.Hash(
  const AData: TBytes;
  const AAlgorithm: TCryptoHashAlgorithm
): TBytes;
begin
  Result := ComputeHash(AData, nil, AAlgorithm, False);
end;

function TCryptoHashService.Hmac(
  const AData, AKey: TBytes;
  const AAlgorithm: TCryptoHashAlgorithm
): TBytes;
begin
  RequireNotEmpty(AKey, 'HMAC key');
  Result := ComputeHash(AData, AKey, AAlgorithm, True);
end;

end.
