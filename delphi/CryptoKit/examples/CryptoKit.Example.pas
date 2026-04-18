unit CryptoKit.Example;

interface

procedure RunCryptoKitExample;

implementation

uses
  System.SysUtils,
  System.Classes,
  CryptoKit,
  CryptoKit.Facade,
  CryptoKit.Types,
  CryptoKit.Encoding;

procedure RunCryptoKitExample;
var
  PlainText: string;
  PlainBytes: TBytes;
  PasswordBytes: TBytes;
  Salt: TBytes;
  Key: TBytes;
  IV: TBytes;
  CipherText: TBytes;
  DecryptedBytes: TBytes;
  HashValue: TBytes;
  HmacValue: TBytes;
  Certs: TCryptoCertificateArray;
  Signature: TBytes;
  Signers: TCryptoCertificateArray;
begin
  PlainText := 'Delphi CryptoKit sample';
  PlainBytes := TEncoding.UTF8.GetBytes(PlainText);
  PasswordBytes := TEncoding.UTF8.GetBytes('StrongPassword');

  Salt := TCryptoKit.RandomBytes(16);
  IV := TCryptoKit.RandomBytes(16);
  Key := TCryptoKit.DeriveKey(PasswordBytes, Salt, 120000, 32, kdfPBKDF2_HMAC_SHA256);

  CipherText := TCryptoKit.EncryptAes256Cbc(PlainBytes, Key, IV);
  DecryptedBytes := TCryptoKit.DecryptAes256Cbc(CipherText, Key, IV);
  HashValue := TCryptoKit.Hash(PlainBytes, haSHA256);
  HmacValue := TCryptoKit.Hmac(PlainBytes, Key, haSHA256);

  Writeln('Plain text       : ' + PlainText);
  Writeln('Cipher (base64)  : ' + BytesToBase64(CipherText));
  Writeln('Decrypted        : ' + TEncoding.UTF8.GetString(DecryptedBytes));
  Writeln('SHA-256 (hex)    : ' + BytesToHex(HashValue));
  Writeln('HMAC-SHA256 (hex): ' + BytesToHex(HmacValue));

  // УКЭП-сценарий: работаем с сертификатом из личного хранилища.
  Certs := TCryptoKit.GetPersonalCertificates(True, slCurrentUser);
  if Length(Certs) > 0 then
  begin
    Signature := TCryptoKit.SignDetached(PlainBytes, Certs[0].Encoded);
    Signers := TCryptoKit.VerifyDetached(PlainBytes, Signature);
    Writeln('Detached sign len: ' + IntToStr(Length(Signature)));
    Writeln('Signer subject   : ' + Certs[0].SubjectName);
    Writeln('Verified signers : ' + IntToStr(Length(Signers)));
  end
  else
    Writeln('No personal certificates with private key found in CurrentUser\MY');
end;

end.
