unit CryptoKit.BCryptApi;

interface

uses
  Winapi.Windows;

type
  NTSTATUS = LongInt;

  BCRYPT_ALG_HANDLE = Pointer;
  PBCRYPT_ALG_HANDLE = ^BCRYPT_ALG_HANDLE;
  BCRYPT_HASH_HANDLE = Pointer;
  PBCRYPT_HASH_HANDLE = ^BCRYPT_HASH_HANDLE;
  BCRYPT_KEY_HANDLE = Pointer;
  PBCRYPT_KEY_HANDLE = ^BCRYPT_KEY_HANDLE;

const
  STATUS_SUCCESS = NTSTATUS($00000000);

  BCRYPT_BLOCK_PADDING = ULONG($00000001);
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = ULONG($00000002);
  BCRYPT_ALG_HANDLE_HMAC_FLAG = ULONG($00000008);

  BCRYPT_SHA256_ALGORITHM: PWideChar = 'SHA256';
  BCRYPT_SHA512_ALGORITHM: PWideChar = 'SHA512';
  BCRYPT_AES_ALGORITHM: PWideChar = 'AES';

  BCRYPT_OBJECT_LENGTH: PWideChar = 'ObjectLength';
  BCRYPT_HASH_LENGTH: PWideChar = 'HashDigestLength';
  BCRYPT_CHAINING_MODE: PWideChar = 'ChainingMode';
  BCRYPT_CHAIN_MODE_CBC: PWideChar = 'ChainingModeCBC';
  BCRYPT_BLOCK_LENGTH: PWideChar = 'BlockLength';
  BCRYPT_KEY_DATA_BLOB: PWideChar = 'KeyDataBlob';

type
  BCRYPT_KEY_DATA_BLOB_HEADER = packed record
    dwMagic: ULONG;
    dwVersion: ULONG;
    cbKeyData: ULONG;
  end;

const
  BCRYPT_KEY_DATA_BLOB_MAGIC = ULONG($4d42444b);
  BCRYPT_KEY_DATA_BLOB_VERSION1 = ULONG($1);

function BCryptOpenAlgorithmProvider(
  phAlgorithm: PBCRYPT_ALG_HANDLE;
  pszAlgId: LPCWSTR;
  pszImplementation: LPCWSTR;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptCloseAlgorithmProvider(
  hAlgorithm: BCRYPT_ALG_HANDLE;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptGetProperty(
  hObject: Pointer;
  pszProperty: LPCWSTR;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  out pcbResult: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptSetProperty(
  hObject: Pointer;
  pszProperty: LPCWSTR;
  pbInput: PUCHAR;
  cbInput: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptCreateHash(
  hAlgorithm: BCRYPT_ALG_HANDLE;
  phHash: PBCRYPT_HASH_HANDLE;
  pbHashObject: PUCHAR;
  cbHashObject: ULONG;
  pbSecret: PUCHAR;
  cbSecret: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptHashData(
  hHash: BCRYPT_HASH_HANDLE;
  pbInput: PUCHAR;
  cbInput: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptFinishHash(
  hHash: BCRYPT_HASH_HANDLE;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptDestroyHash(hHash: BCRYPT_HASH_HANDLE): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptDeriveKeyPBKDF2(
  hPrf: BCRYPT_ALG_HANDLE;
  pbPassword: PUCHAR;
  cbPassword: ULONG;
  pbSalt: PUCHAR;
  cbSalt: ULONG;
  cIterations: UInt64;
  pbDerivedKey: PUCHAR;
  cbDerivedKey: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptGenerateSymmetricKey(
  hAlgorithm: BCRYPT_ALG_HANDLE;
  phKey: PBCRYPT_KEY_HANDLE;
  pbKeyObject: PUCHAR;
  cbKeyObject: ULONG;
  pbSecret: PUCHAR;
  cbSecret: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptImportKey(
  hAlgorithm: BCRYPT_ALG_HANDLE;
  hImportKey: BCRYPT_KEY_HANDLE;
  pszBlobType: LPCWSTR;
  phKey: PBCRYPT_KEY_HANDLE;
  pbKeyObject: PUCHAR;
  cbKeyObject: ULONG;
  pbInput: PUCHAR;
  cbInput: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptEncrypt(
  hKey: BCRYPT_KEY_HANDLE;
  pbInput: PUCHAR;
  cbInput: ULONG;
  pPaddingInfo: Pointer;
  pbIV: PUCHAR;
  cbIV: ULONG;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  out pcbResult: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptDecrypt(
  hKey: BCRYPT_KEY_HANDLE;
  pbInput: PUCHAR;
  cbInput: ULONG;
  pPaddingInfo: Pointer;
  pbIV: PUCHAR;
  cbIV: ULONG;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  out pcbResult: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptDestroyKey(hKey: BCRYPT_KEY_HANDLE): NTSTATUS; stdcall; external 'bcrypt.dll';

function BCryptGenRandom(
  hAlgorithm: BCRYPT_ALG_HANDLE;
  pbBuffer: PUCHAR;
  cbBuffer: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall; external 'bcrypt.dll';

implementation

end.
