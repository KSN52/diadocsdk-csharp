# CryptoKit: сценарии использования (Delphi 10.3.2)

## 1) Основной сценарий ЭДО: УКЭП detached-подпись (как в Диадоке)

Сценарий:
1. Получить сертификат с закрытым ключом из `CurrentUser\MY`.
2. Подписать документ detached-подписью.
3. Передать в ЭДО: `document + signature`.

```pascal
var
  Content: TBytes;
  Certs: TCryptoCertificateArray;
  Signature: TBytes;
begin
  Content := TFile.ReadAllBytes('invoice.xml');
  Certs := TCryptoKit.GetPersonalCertificates(True, slCurrentUser);
  if Length(Certs) = 0 then
    raise Exception.Create('Нет сертификатов с закрытым ключом');

  Signature := TCryptoKit.SignDetached(Content, Certs[0].Encoded);
  TFile.WriteAllBytes('invoice.sig', Signature);
end;
```

## 2) Проверка detached-подписи и извлечение подписантов

Сценарий:
1. Прочитать документ и detached-подпись.
2. Проверить подпись.
3. Получить данные сертификата подписанта.

```pascal
var
  Content: TBytes;
  Signature: TBytes;
  Signers: TCryptoCertificateArray;
begin
  Content := TFile.ReadAllBytes('invoice.xml');
  Signature := TFile.ReadAllBytes('invoice.sig');

  Signers := TCryptoKit.VerifyDetached(Content, Signature);
  Writeln('Signers count: ' + IntToStr(Length(Signers)));
  if Length(Signers) > 0 then
    Writeln('Signer thumbprint: ' + Signers[0].ThumbprintHex);
end;
```

## 3) Выбор сертификата по thumbprint

Используйте, если thumbprint хранится в настройках интеграции.

```pascal
var
  Cert: TCryptoCertificate;
begin
  Cert := TCryptoKit.GetCertificateWithPrivateKeyByThumbprint(
    '0123456789abcdef0123456789abcdef01234567',
    slCurrentUser
  );
  Writeln(Cert.SubjectName);
end;
```

## 4) Совместимый контракт как в оригинальном ICrypt

Для максимальной совместимости используйте `ICryptoService`:

```pascal
var
  Crypt: ICryptoService;
  Signature: TBytes;
  SignerCerts: TCryptoBytesArray;
begin
  Crypt := TCryptoFactory.CreateCryptoService;
  Signature := Crypt.Sign(Content, Cert.Encoded);
  SignerCerts := Crypt.VerifySignature(Content, Signature);
end;
```

Также поддержан reusable-подписант, аналог `ExtendedWinApiCrypt`:

```pascal
var
  ReusableSigner: IExtendedWinApiCryptService;
  Signature: TBytes;
begin
  ReusableSigner := TCryptoFactory.CreateExtendedWinApiCryptService(Cert.Encoded);
  Signature := ReusableSigner.Sign(Content);
end;
```

## 5) Расшифрование через личный сертификат

```pascal
var
  Crypt: ICryptoService;
  Decrypted: TBytes;
begin
  Crypt := TCryptoFactory.CreateCryptoService;
  Decrypted := Crypt.Decrypt(EncryptedBlob, slCurrentUser);
end;
```

## 6) Вспомогательные сценарии (при необходимости)

- Hash: контроль целостности.
- HMAC: подпись внутренних сервисных сообщений.
- PBKDF2 + AES: локальное шифрование данных приложения.
- RNG: генерация salt/IV/токенов.

## 7) Что важно для обратной совместимости

- Формат detached-подписи CMS/PKCS#7 должен оставаться неизменным.
- Thumbprint сертификата храните в нормализованном виде (hex без пробелов, lower-case).
- При расширении сервиса подписи добавляйте новые методы/параметры без удаления существующих контрактов.
- Приоритет выбора хэш-алгоритма подписи для ГОСТ-сертификатов должен оставаться по OID сертификата.
