unit CryptoKit.Bytes;

interface

uses
  System.SysUtils,
  System.Math;

function CompareBytes(const ALeft, ARight: TBytes): Integer;
function EqualBytes(const ALeft, ARight: TBytes): Boolean;

implementation

function CompareBytes(const ALeft, ARight: TBytes): Integer;
var
  I: Integer;
begin
  if Pointer(ALeft) = Pointer(ARight) then
    Exit(0);
  if Length(ALeft) = 0 then
    Exit(Ord(Length(ARight) > 0) * -1);
  if Length(ARight) = 0 then
    Exit(1);

  for I := 0 to Min(Length(ALeft), Length(ARight)) - 1 do
  begin
    Result := ALeft[I] - ARight[I];
    if Result <> 0 then
      Exit;
  end;
  Result := Length(ALeft) - Length(ARight);
end;

function EqualBytes(const ALeft, ARight: TBytes): Boolean;
begin
  Result := CompareBytes(ALeft, ARight) = 0;
end;

end.
