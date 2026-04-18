unit CryptoKit.Factory;

interface

uses
  CryptoKit.Interfaces;

type
  TCryptoFactory = class
  public
    class function CreateHashService: ICryptoHashService; static;
    class function CreateKdfService: ICryptoKdfService; static;
    class function CreateCipherService: ICryptoCipherService; static;
    class function CreateRandomService: ICryptoRandomService; static;
  end;

implementation

uses
  CryptoKit.HashService,
  CryptoKit.KdfService,
  CryptoKit.CipherService,
  CryptoKit.RandomService;

class function TCryptoFactory.CreateHashService: ICryptoHashService;
begin
  Result := TCryptoHashService.Create;
end;

class function TCryptoFactory.CreateKdfService: ICryptoKdfService;
begin
  Result := TCryptoKdfService.Create;
end;

class function TCryptoFactory.CreateCipherService: ICryptoCipherService;
begin
  Result := TCryptoCipherService.Create;
end;

class function TCryptoFactory.CreateRandomService: ICryptoRandomService;
begin
  Result := TCryptoRandomService.Create;
end;

end.
