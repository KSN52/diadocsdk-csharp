unit CryptoKit.Encoding;

interface

uses
  System.SysUtils,
  System.NetEncoding;

function BytesToHex(const AData: TBytes): string;
function HexToBytes(const AHex: string): TBytes;
function BytesToBase64(const AData: TBytes): string;
function Base64ToBytes(const ABase64: string): TBytes;

implementation

function BytesToHex(const AData: TBytes): string;
const
  HexChars: PChar = '0123456789abcdef';
var
  I: Integer;
begin
  SetLength(Result, Length(AData) * 2);
  for I := 0 to Length(AData) - 1 do
  begin
    Result[I * 2 + 1] := HexChars[(AData[I] shr 4) and $0F];
    Result[I * 2 + 2] := HexChars[AData[I] and $0F];
  end;
end;

function HexToBytes(const AHex: string): TBytes;
var
  I: Integer;
  Part: string;
begin
  if (Length(AHex) mod 2) <> 0 then
    raise EConvertError.Create('Hex string length must be even');

  SetLength(Result, Length(AHex) div 2);
  for I := 0 to Length(Result) - 1 do
  begin
    Part := '$' + Copy(AHex, I * 2 + 1, 2);
    Result[I] := StrToInt(Part);
  end;
end;

function BytesToBase64(const AData: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(AData);
end;

function Base64ToBytes(const ABase64: string): TBytes;
begin
  Result := TNetEncoding.Base64.DecodeStringToBytes(ABase64);
end;

end.
