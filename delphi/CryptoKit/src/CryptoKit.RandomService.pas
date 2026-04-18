unit CryptoKit.RandomService;

interface

uses
  CryptoKit.Interfaces;

type
  TCryptoRandomService = class(TInterfacedObject, ICryptoRandomService)
  public
    function GetBytes(const ACount: Integer): TBytes;
  end;

implementation

uses
  Winapi.Windows,
  CryptoKit.BCryptApi,
  CryptoKit.BCryptHelpers,
  CryptoKit.Utils;

function TCryptoRandomService.GetBytes(const ACount: Integer): TBytes;
begin
  EnsureTrue(ACount > 0, 'Random bytes count must be greater than zero');
  SetLength(Result, ACount);
  CheckNtStatus(
    BCryptGenRandom(
      nil,
      BytesPtr(Result),
      Length(Result),
      BCRYPT_USE_SYSTEM_PREFERRED_RNG
    ),
    'BCryptGenRandom'
  );
end;

end.
