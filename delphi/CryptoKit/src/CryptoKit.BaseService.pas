unit CryptoKit.BaseService;

interface

uses
  System.SysUtils;

type
  TCryptoServiceBase = class(TInterfacedObject)
  protected
    procedure RequireTrue(const ACondition: Boolean; const AMessage: string);
    procedure RequireNotEmpty(const AValue: TBytes; const AName: string);
    procedure RequireLength(
      const AValue: TBytes;
      const AExpectedLength: Integer;
      const AName: string
    );
  end;

implementation

uses
  CryptoKit.Utils;

procedure TCryptoServiceBase.RequireTrue(
  const ACondition: Boolean;
  const AMessage: string
);
begin
  EnsureTrue(ACondition, AMessage);
end;

procedure TCryptoServiceBase.RequireNotEmpty(
  const AValue: TBytes;
  const AName: string
);
begin
  EnsureNotEmpty(AValue, AName);
end;

procedure TCryptoServiceBase.RequireLength(
  const AValue: TBytes;
  const AExpectedLength: Integer;
  const AName: string
);
begin
  EnsureLength(AValue, AExpectedLength, AName);
end;

end.
