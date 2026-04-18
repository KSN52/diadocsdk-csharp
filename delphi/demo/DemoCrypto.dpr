program DemoCrypto;

{$APPTYPE CONSOLE}

{$IFDEF MSWINDOWS}
uses
  System.SysUtils,
  System.IOUtils,
  System.Generics.Collections,
  Diadoc.Crypto.Types in '..\src\Diadoc.Crypto.Types.pas',
  Diadoc.Crypto.WinCrypt in '..\src\Diadoc.Crypto.WinCrypt.pas';

var
  Crypt: IDiadocCrypt;
  CertPath, DataPath, Thumb: string;
  CertDER, Content, Sig: TBytes;
  Certs: TList<TBytes>;
  Signed: TSignedContent;
  I: Integer;
  Verified: TList<TBytes>;
begin
  try
    Crypt := TDiadocWinCrypt.Create;

    Writeln('=== Сертификаты в MY с закрытым ключом (текущий пользователь) ===');
    Certs := Crypt.GetPersonalCertificates(True, False);
    try
      Writeln(Format('Найдено: %d', [Certs.Count]));
      for I := 0 to Certs.Count - 1 do
        Writeln(Format('  [%d] DER, %d байт', [I, Length(Certs[I])]));
    finally
      Certs.Free;
    end;

    if ParamCount >= 2 then
    begin
      CertPath := ParamStr(1);
      DataPath := ParamStr(2);
      Thumb := '';
      if (ParamCount >= 3) and ((CertPath = '-') or SameText(CertPath, '/thumb')) then
      begin
        Thumb := ParamStr(3);
        CertDER := Crypt.GetCertificateWithPrivateKey(Thumb, False);
      end
      else
        CertDER := TFile.ReadAllBytes(CertPath);

      Content := TFile.ReadAllBytes(DataPath);
      Sig := Crypt.Sign(Content, CertDER);
      Signed := TSignedContent.Create(Content, Sig);

      TFile.WriteAllBytes(ChangeFileExt(DataPath, '.sig.p7s'), Signed.Signature);
      Writeln(Format('Подпись (отсоединённый PKCS#7): %s, %d байт',
        [ChangeFileExt(DataPath, '.sig.p7s'), Length(Signed.Signature)]));

      Verified := Crypt.VerifySignature(Signed.Content, Signed.Signature);
      try
        Writeln(Format('Проверка: извлечено сертификатов из подписи: %d', [Verified.Count]));
      finally
        Verified.Free;
      end;
    end
    else
    begin
      Writeln;
      Writeln('Подпись файла:');
      Writeln('  DemoCrypto.exe <файл.cer> <данные.bin>');
      Writeln('По SHA1-отпечатку (40 hex):');
      Writeln('  DemoCrypto.exe - <данные.bin> <THUMBPRINT>');
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
{$ELSE}
uses
  System.SysUtils;

begin
  Writeln('Сборка только для Windows (КриптоПро / Crypt32).');
  Readln;
end.
{$ENDIF}
