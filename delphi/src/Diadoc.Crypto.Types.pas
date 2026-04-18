unit Diadoc.Crypto.Types;

{
  Типы, общие с упрощённой моделью Diadoc SignedContent (контент + отсоединённая подпись).
}

interface

uses
  System.SysUtils;

type
  TBytes = TArray<Byte>;

  { Пара контент/подпись для отправки в Diadoc API }
  TSignedContent = record
    Content: TBytes;
    Signature: TBytes;
    class function Create(const AContent, ASignature: TBytes): TSignedContent; static;
  end;

implementation

{ TSignedContent }

class function TSignedContent.Create(const AContent, ASignature: TBytes): TSignedContent;
begin
  Result.Content := AContent;
  Result.Signature := ASignature;
end;

end.
