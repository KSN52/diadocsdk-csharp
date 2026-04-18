# CryptoKit: сценарии использования (Delphi 10.3.2)

## 1) Хеширование данных

Используйте для:
- контроля целостности файлов;
- формирования fingerprint;
- хранения хеша паролей только в сочетании с PBKDF2 (не "сырой" SHA).

```pascal
var
  Digest: TBytes;
begin
  Digest := TCryptoKit.Hash(TEncoding.UTF8.GetBytes('payload'), haSHA256);
end;
```

## 2) HMAC для подписи сообщений

Используйте для:
- подписи API-запросов;
- проверки неизменности сообщений между сервисами;
- защиты от подмены параметров.

```pascal
var
  Signature: TBytes;
  Key: TBytes;
begin
  Key := TCryptoKit.RandomBytes(32);
  Signature := TCryptoKit.Hmac(TEncoding.UTF8.GetBytes('message'), Key, haSHA256);
end;
```

## 3) PBKDF2 для ключей из пароля

Используйте для:
- шифрования пользовательских секретов на основе пароля;
- формирования ключа для AES без хранения "сырого" пароля.

Рекомендация: iterations >= 120000 (подбирайте по производительности).

```pascal
var
  Password, Salt, Key: TBytes;
begin
  Password := TEncoding.UTF8.GetBytes('P@ssw0rd');
  Salt := TCryptoKit.RandomBytes(16);
  Key := TCryptoKit.DeriveKey(Password, Salt, 120000, 32);
end;
```

## 4) Симметричное шифрование AES-256-CBC + PKCS7

Используйте для:
- хранения чувствительных данных в БД;
- шифрования payload перед отправкой;
- защиты документов во временном хранилище.

```pascal
var
  Plain, Key, IV, Cipher, Decoded: TBytes;
begin
  Plain := TEncoding.UTF8.GetBytes('secret');
  Key := TCryptoKit.RandomBytes(32); // 32 bytes
  IV := TCryptoKit.RandomBytes(16);  // 16 bytes for AES block

  Cipher := TCryptoKit.EncryptAes256Cbc(Plain, Key, IV);
  Decoded := TCryptoKit.DecryptAes256Cbc(Cipher, Key, IV);
end;
```

## 5) Генерация криптографически стойких случайных данных

Используйте для:
- IV и salt;
- ключей HMAC;
- одноразовых токенов.

```pascal
var
  Token: TBytes;
begin
  Token := TCryptoKit.RandomBytes(32);
end;
```

## 6) Что важно для обратной совместимости

- Не меняйте длины ключей/IV в уже работающих сценариях без миграции.
- Не меняйте алгоритм PBKDF2 и число итераций для уже сохраненных данных без версии схемы.
- При расширении CryptoKit добавляйте новые enum-значения, не удаляя старые.
