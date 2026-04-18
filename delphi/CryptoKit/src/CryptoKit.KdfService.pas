unit CryptoKit.KdfService;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoKdfService = class(TCryptoServiceBase, ICryptoKdfService)
  private
    function ResolveAlgorithmName(const AAlgorithm: TCryptoKdfAlgorithm): PWideChar;
  public
    function DeriveKey(
      const APassword, ASalt: TBytes;
      const AIterations, AKeyLength: Integer;
      const AAlgorithm: TCryptoKdfAlgorithm = kdfPBKDF2_HMAC_SHA256
    ): TBytes;
  end;

implementation

uses
  Winapi.Windows,
  CryptoKit.BCryptApi,
  CryptoKit.BCryptHelpers,
  CryptoKit.Exceptions,
  CryptoKit.Utils;

function TCryptoKdfService.ResolveAlgorithmName(
  const AAlgorithm: TCryptoKdfAlgorithm
): PWideChar;
begin
  case AAlgorithm of
    kdfPBKDF2_HMAC_SHA256: Result := BCRYPT_SHA256_ALGORITHM;
  else
    raise ECryptoAlgorithmError.Create('Unsupported KDF algorithm');
  end;
end;

function TCryptoKdfService.DeriveKey(
  const APassword, ASalt: TBytes;
  const AIterations, AKeyLength: Integer;
  const AAlgorithm: TCryptoKdfAlgorithm
): TBytes;
var
  AlgHandle: BCRYPT_ALG_HANDLE;
begin
  RequireNotEmpty(APassword, 'PBKDF2 password');
  RequireNotEmpty(ASalt, 'PBKDF2 salt');
  RequireTrue(AIterations > 0, 'PBKDF2 iterations must be greater than zero');
  RequireTrue(AKeyLength > 0, 'PBKDF2 key length must be greater than zero');

  AlgHandle := nil;
  CheckNtStatus(
    BCryptOpenAlgorithmProvider(
      @AlgHandle,
      ResolveAlgorithmName(AAlgorithm),
      nil,
      BCRYPT_ALG_HANDLE_HMAC_FLAG
    ),
    'BCryptOpenAlgorithmProvider'
  );
  try
    SetLength(Result, AKeyLength);
    CheckNtStatus(
      BCryptDeriveKeyPBKDF2(
        AlgHandle,
        BytesPtr(APassword),
        Length(APassword),
        BytesPtr(ASalt),
        Length(ASalt),
        UInt64(AIterations),
        BytesPtr(Result),
        Length(Result),
        0
      ),
      'BCryptDeriveKeyPBKDF2'
    );
  finally
    BCryptCloseAlgorithmProvider(AlgHandle, 0);
  end;
end;

end.
