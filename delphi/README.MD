# Упрощённый Delphi SDK (криптография Диадок / порт WinApiCrypt)

## Назначение

Порт логики `Diadoc.Api.Cryptography` из репозитория **diadocsdk-csharp**: отсоединённая подпись PKCS#7 через `CryptSignMessage`, проверка, расшифровка CMS, поиск сертификата с закрытым ключом по DER или отпечатку SHA1 (как `CertificateWithPrivateKeyFinder` + `WinApiCrypt`).

**Не входит:** HTTP к Diadoc, protobuf, `PostMessage` — для этого по-прежнему нужен полный API (или отдельный модуль с protobuf).

## Структура

```
delphi/
  README.MD                 — этот файл
  src/
    Diadoc.Crypto.Types.pas — TSignedContent (контент + подпись)
    Diadoc.Crypto.WinCrypt.pas — IDiadocCrypt, TDiadocWinCrypt (только {$IFDEF MSWINDOWS})
  demo/
    DemoCrypto.dpr          — консоль: список MY, подпись файла, проверка
```

## Требования

- **Windows** (x32/x64), RAD Studio **10.3.x** или новее.
- Установленный **КриптоПро CSP** (или совместимый), сертификат с ключом в хранилище **MY**.

## Сборка

1. Откройте `demo/DemoCrypto.dpr` в IDE.
2. Платформа: **Windows 32** или **Windows 64**.
3. Скомпилируйте и запустите.

## Примеры

```text
DemoCrypto.exe
```

Выводит количество сертификатов в MY с закрытым ключом.

```text
DemoCrypto.exe public.cer document.xml
```

Подписывает `document.xml` сертификатом из `public.cer` (закрытый ключ ищется в MY/ROOT/CA/AddressBook текущего пользователя и локальной машины, как в C# SDK). Подпись: `document.sig.p7s`.

```text
DemoCrypto.exe - document.xml A1B2C3D4E5F6789012345678901234567890ABCD
```

То же по **SHA1 thumbprint** (40 hex без пробелов; пробелы в строке игнорируются при сравнении).

## Интеграция в свой проект

Добавьте в `uses` модули из `src/`, создайте:

```pascal
var
  Crypt: IDiadocCrypt;
begin
  Crypt := TDiadocWinCrypt.Create;
  Signature := Crypt.Sign(DocumentBytes, CertificateDER);
end;
```

Поле `Signature` передавайте в protobuf `SignedContent.Signature` при отправке через API Диадока.

## Правила кода

- Не менять вызовы `CryptSignMessage` / `CryptVerifyDetachedMessageSignature`: сигнатуры должны совпадать с `Winapi.Wincrypt`.
- OID ГОСТ для хэша — как в C# `WinApiCrypt.MapSignatureOidToHashOid`.
