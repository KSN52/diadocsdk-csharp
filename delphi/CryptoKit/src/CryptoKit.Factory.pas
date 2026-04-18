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
    class function CreateCertificateService: ICryptoCertificateService; static;
    class function CreateSignatureService: ICryptoSignatureService; static;
  end;

implementation

uses
  CryptoKit.HashService,
  CryptoKit.KdfService,
  CryptoKit.CipherService,
  CryptoKit.RandomService,
  CryptoKit.CertificateService,
  CryptoKit.SignatureService;

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

class function TCryptoFactory.CreateCertificateService: ICryptoCertificateService;
begin
  Result := TCryptoCertificateService.Create;
end;

class function TCryptoFactory.CreateSignatureService: ICryptoSignatureService;
begin
  Result := TCryptoSignatureService.Create;
end;

end.
