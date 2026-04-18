unit CryptoKit.BCryptHelpers;

interface

uses
  System.SysUtils,
  Winapi.Windows,
  CryptoKit.BCryptApi,
  CryptoKit.Exceptions;

procedure CheckNtStatus(const AStatus: NTSTATUS; const AContext: string);
function ReadAlgorithmDwordProperty(
  const AHandle: BCRYPT_ALG_HANDLE;
  const APropertyName: PWideChar
): Cardinal;

implementation

procedure CheckNtStatus(const AStatus: NTSTATUS; const AContext: string);
begin
  if AStatus <> STATUS_SUCCESS then
    raise ECryptoPlatformError.CreateFmt(
      '%s failed with NTSTATUS 0x%.8x',
      [AContext, Cardinal(AStatus)]
    );
end;

function ReadAlgorithmDwordProperty(
  const AHandle: BCRYPT_ALG_HANDLE;
  const APropertyName: PWideChar
): Cardinal;
var
  PropertyValue: Cardinal;
  BytesWritten: ULONG;
begin
  BytesWritten := 0;
  CheckNtStatus(
    BCryptGetProperty(
      AHandle,
      APropertyName,
      @PropertyValue,
      SizeOf(PropertyValue),
      BytesWritten,
      0
    ),
    'BCryptGetProperty(' + string(APropertyName) + ')'
  );
  Result := PropertyValue;
end;

end.
