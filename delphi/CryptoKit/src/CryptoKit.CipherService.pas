unit CryptoKit.CipherService;

interface

uses
  System.SysUtils,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoCipherService = class(TCryptoServiceBase, ICryptoCipherService)
  private
    function ResolveAlgorithmName(const AAlgorithm: TCryptoCipherAlgorithm): PWideChar;
    function BuildKeyBlob(const AKey: TBytes): TBytes;
    function ProcessAesCbc(
      const AInput: TBytes;
      const AParams: TCryptoAesParams;
      const AEncrypt: Boolean
    ): TBytes;
  public
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

implementation

uses
  Winapi.Windows,
  CryptoKit.BCryptApi,
  CryptoKit.BCryptHelpers,
  CryptoKit.Exceptions,
  CryptoKit.Utils;

function TCryptoCipherService.ResolveAlgorithmName(
  const AAlgorithm: TCryptoCipherAlgorithm
): PWideChar;
begin
  case AAlgorithm of
    caAES256_CBC_PKCS7: Result := BCRYPT_AES_ALGORITHM;
  else
    raise ECryptoAlgorithmError.Create('Unsupported cipher algorithm');
  end;
end;

function TCryptoCipherService.BuildKeyBlob(const AKey: TBytes): TBytes;
var
  Header: BCRYPT_KEY_DATA_BLOB_HEADER;
begin
  Header.dwMagic := BCRYPT_KEY_DATA_BLOB_MAGIC;
  Header.dwVersion := BCRYPT_KEY_DATA_BLOB_VERSION1;
  Header.cbKeyData := Length(AKey);

  SetLength(Result, SizeOf(Header) + Length(AKey));
  Move(Header, Result[0], SizeOf(Header));
  if Length(AKey) > 0 then
    Move(AKey[0], Result[SizeOf(Header)], Length(AKey));
end;

function TCryptoCipherService.ProcessAesCbc(
  const AInput: TBytes;
  const AParams: TCryptoAesParams;
  const AEncrypt: Boolean
): TBytes;
var
  AlgHandle: BCRYPT_ALG_HANDLE;
  KeyHandle: BCRYPT_KEY_HANDLE;
  KeyBlob: TBytes;
  KeyObject: TBytes;
  KeyObjectLength: Cardinal;
  BlockLength: Cardinal;
  IVBuffer: TBytes;
  OutputSize: ULONG;
  ChainingModeValue: UnicodeString;
begin
  RequireLength(AParams.Key, 32, 'AES-256 key');
  RequireNotEmpty(AParams.IV, 'AES IV');

  AlgHandle := nil;
  KeyHandle := nil;

  CheckNtStatus(
    BCryptOpenAlgorithmProvider(
      @AlgHandle,
      BCRYPT_AES_ALGORITHM,
      nil,
      0
    ),
    'BCryptOpenAlgorithmProvider'
  );
  try
    ChainingModeValue := BCRYPT_CHAIN_MODE_CBC;
    CheckNtStatus(
      BCryptSetProperty(
        AlgHandle,
        BCRYPT_CHAINING_MODE,
        PUCHAR(PWideChar(ChainingModeValue)),
        (Length(ChainingModeValue) + 1) * SizeOf(WideChar),
        0
      ),
      'BCryptSetProperty(BCRYPT_CHAINING_MODE)'
    );

    BlockLength := ReadAlgorithmDwordProperty(AlgHandle, BCRYPT_BLOCK_LENGTH);
    RequireLength(AParams.IV, BlockLength, 'AES IV');
    KeyObjectLength := ReadAlgorithmDwordProperty(AlgHandle, BCRYPT_OBJECT_LENGTH);

    KeyBlob := BuildKeyBlob(AParams.Key);
    SetLength(KeyObject, KeyObjectLength);

    CheckNtStatus(
      BCryptImportKey(
        AlgHandle,
        nil,
        BCRYPT_KEY_DATA_BLOB,
        @KeyHandle,
        BytesPtr(KeyObject),
        Length(KeyObject),
        BytesPtr(KeyBlob),
        Length(KeyBlob),
        0
      ),
      'BCryptImportKey'
    );
    try
      IVBuffer := CloneBytes(AParams.IV);
      OutputSize := 0;
      if AEncrypt then
      begin
        // Для пустого plaintext BCrypt требует минимум 1 блок c PKCS7 padding.
        if Length(AInput) = 0 then
          OutputSize := BlockLength
        else
          OutputSize := Cardinal(((Length(AInput) div Integer(BlockLength)) + 1) * BlockLength);

        CheckNtStatus(
          BCryptEncrypt(
            KeyHandle,
            BytesPtr(AInput),
            Length(AInput),
            nil,
            BytesPtr(IVBuffer),
            Length(IVBuffer),
            nil,
            0,
            OutputSize,
            BCRYPT_BLOCK_PADDING
          ),
          'BCryptEncrypt(size)'
        );

        SetLength(Result, OutputSize);
        CheckNtStatus(
          BCryptEncrypt(
            KeyHandle,
            BytesPtr(AInput),
            Length(AInput),
            nil,
            BytesPtr(IVBuffer),
            Length(IVBuffer),
            BytesPtr(Result),
            Length(Result),
            OutputSize,
            BCRYPT_BLOCK_PADDING
          ),
          'BCryptEncrypt'
        );
      end
      else
      begin
        RequireTrue((Length(AInput) mod Integer(BlockLength)) = 0, 'Cipher text length must be multiple of block size');
        CheckNtStatus(
          BCryptDecrypt(
            KeyHandle,
            BytesPtr(AInput),
            Length(AInput),
            nil,
            BytesPtr(IVBuffer),
            Length(IVBuffer),
            nil,
            0,
            OutputSize,
            BCRYPT_BLOCK_PADDING
          ),
          'BCryptDecrypt(size)'
        );

        SetLength(Result, OutputSize);
        CheckNtStatus(
          BCryptDecrypt(
            KeyHandle,
            BytesPtr(AInput),
            Length(AInput),
            nil,
            BytesPtr(IVBuffer),
            Length(IVBuffer),
            BytesPtr(Result),
            Length(Result),
            OutputSize,
            BCRYPT_BLOCK_PADDING
          ),
          'BCryptDecrypt'
        );
      end;

      SetLength(Result, OutputSize);
    finally
      BCryptDestroyKey(KeyHandle);
    end;
  finally
    BCryptCloseAlgorithmProvider(AlgHandle, 0);
  end;
end;

function TCryptoCipherService.Encrypt(
  const APlainData: TBytes;
  const AParams: TCryptoAesParams;
  const AAlgorithm: TCryptoCipherAlgorithm
): TBytes;
begin
  ResolveAlgorithmName(AAlgorithm);
  Result := ProcessAesCbc(APlainData, AParams, True);
end;

function TCryptoCipherService.Decrypt(
  const ACipherData: TBytes;
  const AParams: TCryptoAesParams;
  const AAlgorithm: TCryptoCipherAlgorithm
): TBytes;
begin
  ResolveAlgorithmName(AAlgorithm);
  RequireNotEmpty(ACipherData, 'Cipher text');
  Result := ProcessAesCbc(ACipherData, AParams, False);
end;

end.
