unit CryptoKit.Utils;

interface

uses
  System.SysUtils,
  Winapi.Windows,
  CryptoKit.Exceptions;

procedure EnsureTrue(const ACondition: Boolean; const AMessage: string);
procedure EnsureNotEmpty(const AValue: TBytes; const AName: string);
procedure EnsureLength(
  const AValue: TBytes;
  const AExpectedLength: Integer;
  const AName: string
);
function BytesPtr(const AData: TBytes): PUCHAR;

implementation

procedure EnsureTrue(const ACondition: Boolean; const AMessage: string);
begin
  if not ACondition then
    raise ECryptoValidationError.Create(AMessage);
end;

procedure EnsureNotEmpty(const AValue: TBytes; const AName: string);
begin
  EnsureTrue(Length(AValue) > 0, AName + ' must not be empty');
end;

procedure EnsureLength(
  const AValue: TBytes;
  const AExpectedLength: Integer;
  const AName: string
);
begin
  EnsureTrue(
    Length(AValue) = AExpectedLength,
    Format('%s must be %d bytes long', [AName, AExpectedLength])
  );
end;

function BytesPtr(const AData: TBytes): PUCHAR;
begin
  if Length(AData) = 0 then
    Exit(nil);
  Result := @AData[0];
end;

end.
