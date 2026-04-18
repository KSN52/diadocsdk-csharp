unit CryptoKit.Exceptions;

interface

uses
  System.SysUtils;

type
  ECryptoKitError = class(Exception);
  ECryptoValidationError = class(ECryptoKitError);
  ECryptoAlgorithmError = class(ECryptoKitError);
  ECryptoPlatformError = class(ECryptoKitError);

implementation

end.
