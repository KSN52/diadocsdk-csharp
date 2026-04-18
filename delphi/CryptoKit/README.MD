# CryptoKit (Delphi 10.3.2)

Переиспользуемый модульный набор криптографии для Delphi 10.3.2, ориентированный в первую очередь на сценарии УКЭП (электронный документооборот, подпись, сертификаты, ключи), готовый для подключения в другие проекты.

## Очень важная информация по проекту

### 1. Структура каталогов

```text
delphi/CryptoKit/
  README.MD
  docs/
    USAGE_SCENARIOS.md
  examples/
    CryptoKit.Example.pas
  src/
    CryptoKit.dpk
    CryptoKit.pas
    CryptoKit.Types.pas
    CryptoKit.Exceptions.pas
    CryptoKit.Interfaces.pas
    CryptoKit.Utils.pas
    CryptoKit.BaseService.pas
    CryptoKit.BCryptApi.pas
    CryptoKit.BCryptHelpers.pas
    CryptoKit.CryptApi.pas
    CryptoKit.HashService.pas
    CryptoKit.KdfService.pas
    CryptoKit.CipherService.pas
    CryptoKit.RandomService.pas
    CryptoKit.CertificateService.pas
    CryptoKit.SignatureService.pas
    CryptoKit.Encoding.pas
    CryptoKit.Factory.pas
    CryptoKit.Facade.pas
```

### 2. Архитектура проекта

- **Контрактный слой**:
  - `CryptoKit.Interfaces.pas` — интерфейсы сервисов (`ICryptoHashService`, `ICryptoKdfService`, `ICryptoCipherService`, `ICryptoRandomService`, `ICryptoCertificateService`, `ICryptoSignatureService`).
  - `CryptoKit.Types.pas` — enum алгоритмов и параметры AES.
- **Базовый инфраструктурный слой**:
  - `CryptoKit.Exceptions.pas` — типы исключений.
  - `CryptoKit.Utils.pas` + `CryptoKit.BaseService.pas` — валидация входных параметров.
- **Платформенный слой**:
  - `CryptoKit.BCryptApi.pas` — объявления WinAPI BCrypt.
  - `CryptoKit.BCryptHelpers.pas` — проверки `NTSTATUS`, чтение свойств алгоритмов.
  - `CryptoKit.CryptApi.pas` — объявления WinAPI Crypt32 для PKCS#7 detached-подписи и сертификатов.
- **Слой реализаций**:
  - `CryptoKit.HashService.pas` — SHA-256/SHA-512, HMAC.
  - `CryptoKit.KdfService.pas` — PBKDF2-HMAC-SHA256.
  - `CryptoKit.CipherService.pas` — AES-256-CBC + PKCS7.
  - `CryptoKit.RandomService.pas` — криптостойкий RNG.
  - `CryptoKit.CertificateService.pas` — работа с сертификатами из MY-хранилища.
  - `CryptoKit.SignatureService.pas` — detached-подпись и проверка подписи (под УКЭП сценарии).
- **Слой интеграции и фасад**:
  - `CryptoKit.Factory.pas` — фабрика сервисов.
  - `CryptoKit.Facade.pas` — статический фасад `TCryptoKit` для быстрого использования.
  - `CryptoKit.Encoding.pas` — Base64/Hex преобразования.
  - `CryptoKit.pas` — unit-агрегатор.

### 3. Правила написания кода

- Delphi 10.3.2 совместимость:
  - без новых языковых возможностей более поздних версий;
  - только стандартные RTL/VCL и WinAPI.
- Явная валидация входных данных перед криптооперациями.
- Ошибки платформы всегда поднимаются через `ECryptoPlatformError` с контекстом вызова.
- Криптографические константы (длина ключа/IV, режим шифрования) не изменяются без версии API.
- Публичные контракты через интерфейсы; реализации можно подменять без ломки внешнего кода.

### 4. Шаблоны работы с кодом

- **Шаблон подключения в другой проект**:
  1. Добавить `delphi/CryptoKit/src` в `Search Path`.
  2. Подключить unit `CryptoKit`.
  3. Вызывать фасад `TCryptoKit` или фабрику `TCryptoFactory`.
- **Шаблон безопасного шифрования паролем**:
  1. Сгенерировать `Salt` (`RandomBytes(16)`).
  2. Вычислить ключ через `DeriveKey(password, salt, iterations, 32)`.
  3. Сгенерировать `IV` (`RandomBytes(16)`).
  4. Выполнить `EncryptAes256Cbc`.
  5. Хранить `salt + iv + ciphertext` вместе с версией схемы.
- **Шаблон расширения функциональности**:
  - добавить новый enum в `CryptoKit.Types`;
  - расширить соответствующий service;
  - не удалять существующие enum/методы;
  - дополнить `USAGE_SCENARIOS.md`.
- **Шаблон УКЭП-подписания (как в ЭДО)**:
  1. Получить сертификаты с закрытым ключом `GetPersonalCertificates(True)`.
  2. Выбрать сертификат по thumbprint или бизнес-правилам.
  3. Выполнить `SignDetached(content, cert.Encoded)`.
  4. На стороне проверки вызвать `VerifyDetached(content, signature)` и сверить signer certificate.

## Реализованные криптосценарии

- УКЭП-базовые операции:
  - перечисление личных сертификатов (CurrentUser/LocalMachine, хранилище MY);
  - отбор сертификата по thumbprint с закрытым ключом;
  - detached PKCS#7 подпись;
  - проверка detached-подписи с извлечением сертификатов подписантов.
- Hash: SHA-256, SHA-512.
- MAC: HMAC-SHA256, HMAC-SHA512.
- KDF: PBKDF2-HMAC-SHA256.
- Cipher: AES-256-CBC-PKCS7.
- RNG: криптографический генератор случайных байт.
- Encoding: Base64/Hex.

## Анализ зависимостей

- **Внутренние зависимости**: только модули `CryptoKit.*`.
- **Внешние зависимости**:
  - `bcrypt.dll` (Windows CNG);
  - `crypt32.dll` (Windows CryptoAPI для подписи/сертификатов);
  - `rtl`, `vcl`.
- **Совместимость**:
  - API-модулей построен на интерфейсах и enum: возможно расширение без breaking changes;
  - добавленные методы для сертификатов/подписи расширяют функциональность без изменения ранее добавленных методов.

