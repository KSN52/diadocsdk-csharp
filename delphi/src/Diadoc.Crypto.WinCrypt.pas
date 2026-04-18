unit Diadoc.Crypto.WinCrypt;

{
  Порт логики Diadoc.Api.Cryptography.WinApiCrypt + CertificateWithPrivateKeyFinder.
  Требуется Windows и установленный CSP (КриптоПро и т.п.) с сертификатом в MY.
}

interface

{$IFDEF MSWINDOWS}

uses
  System.SysUtils,
  System.Math,
  System.Generics.Collections,
  Winapi.Windows,
  Winapi.Wincrypt,
  Diadoc.Crypto.Types;

type
  EDiadocCrypto = class(Exception);

  { Интерфейс, аналогичный ICrypt из C# SDK }
  IDiadocCrypt = interface
    ['{B4F8C9A1-2E3D-4F5A-9B0C-1D2E3F4A5B6C}']
    function Sign(const Content: TBytes; const CertificateDER: TBytes): TBytes;
    function VerifySignature(const Content, Signature: TBytes): TList<TBytes>;
    function Decrypt(const EncryptedContent: TBytes; UseLocalMachineStore: Boolean): TBytes;
    function GetPersonalCertificates(OnlyWithPrivateKey: Boolean; UseLocalMachineStore: Boolean): TList<TBytes>;
    function GetCertificateWithPrivateKey(const ThumbprintHex: string; UseLocalMachineStore: Boolean): TBytes;
  end;

  TDiadocWinCrypt = class(TInterfacedObject, IDiadocCrypt)
  private
    class function CertHash(const CertContext: PCCERT_CONTEXT): TBytes; static;
    class function BytesCompare(const A, B: TBytes): Integer; static;
    class function MapSignatureOidToHashOid(const SigOid: AnsiString): AnsiString; static;
    class function GetHashAlgorithmOid(CertContext: PCCERT_CONTEXT): AnsiString; static;
    function OpenMyStore(UseLocalMachineStore: Boolean): HCERTSTORE;
    procedure CloseStore(Store: HCERTSTORE);
    function HasPrivateKey(CertContext: PCCERT_CONTEXT): Boolean;
    function FindCertificateWithPrivateKey(InitialCert: PCCERT_CONTEXT): PCCERT_CONTEXT;
    function GetCertificateWithPrivateKeyPtr(const CertificateDER: TBytes): PCCERT_CONTEXT;
  public
    function Sign(const Content: TBytes; const CertificateDER: TBytes): TBytes;
    function VerifySignature(const Content, Signature: TBytes): TList<TBytes>;
    function Decrypt(const EncryptedContent: TBytes; UseLocalMachineStore: Boolean): TBytes;
    function GetPersonalCertificates(OnlyWithPrivateKey: Boolean; UseLocalMachineStore: Boolean): TList<TBytes>;
    function GetCertificateWithPrivateKey(const ThumbprintHex: string; UseLocalMachineStore: Boolean): TBytes;
  end;

{$ELSE}

type
  EDiadocCrypto = class(Exception);

{$ENDIF MSWINDOWS}

implementation

{$IFDEF MSWINDOWS}

uses
  System.StrUtils;

const
  CERT_ENCODING = X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;

  OID_GOST_34_11_94: AnsiString = '1.2.643.2.2.9';
  OID_GOST_34_11_12_256: AnsiString = '1.2.643.7.1.1.2.2';
  OID_GOST_34_11_12_512: AnsiString = '1.2.643.7.1.1.2.3';
  OID_GOST_34_11_94_R3410EL: AnsiString = '1.2.643.2.2.3';
  OID_GOST_34_11_12_256_R3410: AnsiString = '1.2.643.7.1.1.3.2';
  OID_GOST_34_11_12_512_R3410: AnsiString = '1.2.643.7.1.1.3.3';

{ TDiadocWinCrypt }

class function TDiadocWinCrypt.BytesCompare(const A, B: TBytes): Integer;
var
  I, L: Integer;
begin
  if Pointer(A) = Pointer(B) then
    Exit(0);
  if A = nil then
    Exit(-1);
  if B = nil then
    Exit(1);
  L := Min(Length(A), Length(B));
  for I := 0 to L - 1 do
  begin
    if A[I] < B[I] then
      Exit(-1);
    if A[I] > B[I] then
      Exit(1);
  end;
  Result := CompareValue(Length(A), Length(B));
end;

class function TDiadocWinCrypt.MapSignatureOidToHashOid(const SigOid: AnsiString): AnsiString;
begin
  if SigOid = OID_GOST_34_11_94_R3410EL then
    Exit(OID_GOST_34_11_94);
  if SigOid = OID_GOST_34_11_12_256_R3410 then
    Exit(OID_GOST_34_11_12_256);
  if SigOid = OID_GOST_34_11_12_512_R3410 then
    Exit(OID_GOST_34_11_12_512);
  Result := OID_GOST_34_11_94;
end;

class function TDiadocWinCrypt.GetHashAlgorithmOid(CertContext: PCCERT_CONTEXT): AnsiString;
var
  Info: PCERT_INFO;
  SigAlg: AnsiString;
begin
  if (CertContext = nil) or (CertContext^.pCertInfo = nil) then
    Exit(OID_GOST_34_11_94);
  Info := CertContext^.pCertInfo;
  SigAlg := AnsiString(Info^.SignatureAlgorithm.pszObjId);
  Result := MapSignatureOidToHashOid(SigAlg);
end;

class function TDiadocWinCrypt.CertHash(const CertContext: PCCERT_CONTEXT): TBytes;
var
  Sz: DWORD;
begin
  Sz := 0;
  if not CertGetCertificateContextProperty(CertContext, CERT_HASH_PROP_ID, nil, Sz) then
  begin
    if GetLastError <> ERROR_INSUFFICIENT_BUFFER then
      RaiseLastOSError;
  end;
  SetLength(Result, Sz);
  if not CertGetCertificateContextProperty(CertContext, CERT_HASH_PROP_ID, @Result[0], Sz) then
    RaiseLastOSError;
end;

function TDiadocWinCrypt.HasPrivateKey(CertContext: PCCERT_CONTEXT): Boolean;
var
  Sz: DWORD;
  Err: DWORD;
begin
  Sz := 0;
  if CertGetCertificateContextProperty(CertContext, CERT_KEY_PROV_INFO_PROP_ID, nil, Sz) then
    Exit(True);
  Err := GetLastError;
  if Err = DWORD($80092004) then // CRYPT_E_NOT_FOUND — свойства нет
    Exit(False);
  if Err = ERROR_INSUFFICIENT_BUFFER then // размер запрошен, ключ есть
    Exit(True);
  RaiseOSError(Err);
end;

function TDiadocWinCrypt.OpenMyStore(UseLocalMachineStore: Boolean): HCERTSTORE;
var
  Flags: DWORD;
begin
  Flags := CERT_STORE_READONLY_FLAG;
  if UseLocalMachineStore then
    Flags := Flags or CERT_SYSTEM_STORE_LOCAL_MACHINE
  else
    Flags := Flags or CERT_SYSTEM_STORE_CURRENT_USER;
  Result := CertOpenStore(CERT_STORE_PROV_SYSTEM_W, CERT_ENCODING, 0, Flags, PWideChar('MY'));
  if Result = nil then
    RaiseLastOSError;
end;

procedure TDiadocWinCrypt.CloseStore(Store: HCERTSTORE);
begin
  if Store <> nil then
    CertCloseStore(Store, 0);
end;

function TDiadocWinCrypt.FindCertificateWithPrivateKey(InitialCert: PCCERT_CONTEXT): PCCERT_CONTEXT;
const
  StoreNames: array [0 .. 3] of string = ('MY', 'ROOT', 'CA', 'ADDRESSBOOK');
var
  TargetHash: TBytes;
  StoreFlags: array [0 .. 1] of DWORD;
  I, J: Integer;
  Store: HCERTSTORE;
  EnumCtx, DupCtx: PCCERT_CONTEXT;
  Err: DWORD;
begin
  Result := nil;
  TargetHash := CertHash(InitialCert);
  StoreFlags[0] := CERT_SYSTEM_STORE_CURRENT_USER;
  StoreFlags[1] := CERT_SYSTEM_STORE_LOCAL_MACHINE;

  for I := Low(StoreFlags) to High(StoreFlags) do
    for J := Low(StoreNames) to High(StoreNames) do
    begin
      Store := CertOpenStore(CERT_STORE_PROV_SYSTEM_W, CERT_ENCODING, 0,
        CERT_STORE_READONLY_FLAG or StoreFlags[I], PWideChar(StoreNames[J]));
      if Store = nil then
        Continue;
      try
        EnumCtx := nil;
        repeat
          EnumCtx := CertEnumCertificatesInStore(Store, EnumCtx);
          if EnumCtx = nil then
          begin
            Err := GetLastError;
            if (Err = DWORD($80092004)) or (Err = ERROR_NO_MORE_FILES) then
              Break;
            if Err <> 0 then
              RaiseOSError(Err);
            Break;
          end;
          DupCtx := CertDuplicateCertificateContext(EnumCtx);
          try
            if HasPrivateKey(DupCtx) and (BytesCompare(CertHash(DupCtx), TargetHash) = 0) then
            begin
              Result := DupCtx;
              DupCtx := nil;
              Exit;
            end;
          finally
            if DupCtx <> nil then
              CertFreeCertificateContext(DupCtx);
          end;
        until False;
      finally
        CloseStore(Store);
      end;
    end;
end;

function TDiadocWinCrypt.GetCertificateWithPrivateKeyPtr(const CertificateDER: TBytes): PCCERT_CONTEXT;
var
  Ctx: PCCERT_CONTEXT;
begin
  if Length(CertificateDER) = 0 then
    raise EDiadocCrypto.Create('Пустой сертификат');
  Ctx := CertCreateCertificateContext(CERT_ENCODING, @CertificateDER[0], Length(CertificateDER));
  if Ctx = nil then
    RaiseLastOSError;
  try
    if HasPrivateKey(Ctx) then
      Exit(CertDuplicateCertificateContext(Ctx));
    Result := FindCertificateWithPrivateKey(Ctx);
    if Result = nil then
      raise EDiadocCrypto.Create('Сертификат с закрытым ключом не найден');
  finally
    CertFreeCertificateContext(Ctx);
  end;
end;

function TDiadocWinCrypt.Sign(const Content: TBytes; const CertificateDER: TBytes): TBytes;
var
  CertCtx: PCCERT_CONTEXT;
  MsgCert: PCCERT_CONTEXT;
  HashOid: AnsiString;
  HashAlg: CRYPT_ALGORITHM_IDENTIFIER;
  SignPara: CRYPT_SIGN_MESSAGE_PARA;
  ContentPtrs: array [0 .. 0] of PByte;
  ContentLens: array [0 .. 0] of DWORD;
  SigSize: DWORD;
  BufCap: DWORD;
  LastWin32: DWORD;
begin
  CertCtx := GetCertificateWithPrivateKeyPtr(CertificateDER);
  MsgCert := CertDuplicateCertificateContext(CertCtx);
  try
    FillChar(HashAlg, SizeOf(HashAlg), 0);
    HashOid := GetHashAlgorithmOid(CertCtx);
    HashAlg.pszObjId := PAnsiChar(Pointer(HashOid));

    FillChar(SignPara, SizeOf(SignPara), 0);
    SignPara.cbSize := SizeOf(SignPara);
    SignPara.dwMsgEncodingType := CERT_ENCODING;
    SignPara.pSigningCert := CertCtx;
    SignPara.HashAlgorithm := HashAlg;
    SignPara.cMsgCert := 1;
    SignPara.rgpMsgCert := @MsgCert;

    if Length(Content) = 0 then
      raise EDiadocCrypto.Create('Пустой контент для подписи');

    ContentPtrs[0] := @Content[0];
    ContentLens[0] := Length(Content);

    SigSize := 0;
    if not CryptSignMessage(@SignPara, True, 1, @ContentPtrs[0], @ContentLens[0], nil, @SigSize) then
      RaiseLastOSError;

    BufCap := SigSize + 1024;
    while True do
    begin
      SetLength(Result, BufCap);
      SigSize := BufCap;
      if CryptSignMessage(@SignPara, True, 1, @ContentPtrs[0], @ContentLens[0], @Result[0], @SigSize) then
      begin
        SetLength(Result, SigSize);
        Break;
      end;
      LastWin32 := GetLastError;
      if LastWin32 = ERROR_MORE_DATA then
        BufCap := BufCap * 2
      else
        RaiseOSError(LastWin32);
    end;
  finally
    CertFreeCertificateContext(MsgCert);
    CertFreeCertificateContext(CertCtx);
  end;
end;

function TDiadocWinCrypt.VerifySignature(const Content, Signature: TBytes): TList<TBytes>;
var
  VerifyPara: CRYPT_VERIFY_MESSAGE_PARA;
  SignerIdx: DWORD;
  SignerCert: PCCERT_CONTEXT;
  ContentPtrs: array [0 .. 0] of PByte;
  ContentLens: array [0 .. 0] of DWORD;
  DER: TBytes;
  Err: DWORD;
begin
  Result := TList<TBytes>.Create;
  if Length(Content) = 0 then
    raise EDiadocCrypto.Create('Пустой контент');
  if Length(Signature) = 0 then
    raise EDiadocCrypto.Create('Пустая подпись');

  FillChar(VerifyPara, SizeOf(VerifyPara), 0);
  VerifyPara.cbSize := SizeOf(VerifyPara);
  VerifyPara.dwMsgEncodingType := CERT_ENCODING;

  ContentPtrs[0] := @Content[0];
  ContentLens[0] := Length(Content);

  SignerIdx := 0;
  while True do
  begin
    SignerCert := nil;
    if not CryptVerifyDetachedMessageSignature(@VerifyPara, SignerIdx, @Signature[0],
      Length(Signature), 1, @ContentPtrs[0], @ContentLens[0], @SignerCert) then
    begin
      Err := GetLastError;
      if Err = DWORD($8009200E) then // CRYPT_E_NO_SIGNER
        Break;
      if Err = DWORD($80090006) then // NTE_BAD_SIGNATURE
        raise EDiadocCrypto.Create('Неверная подпись');
      RaiseOSError(Err);
    end;
    try
      SetLength(DER, SignerCert^.cbCertEncoded);
      Move(SignerCert^.pbCertEncoded^, DER[0], SignerCert^.cbCertEncoded);
      Result.Add(DER);
    finally
      if SignerCert <> nil then
        CertFreeCertificateContext(SignerCert);
    end;
    Inc(SignerIdx);
  end;
end;

function TDiadocWinCrypt.Decrypt(const EncryptedContent: TBytes; UseLocalMachineStore: Boolean): TBytes;
var
  Store: HCERTSTORE;
  DecryptPara: CRYPT_DECRYPT_MESSAGE_PARA;
  OutLen: DWORD;
  LastWin32: DWORD;
begin
  if Length(EncryptedContent) = 0 then
    raise EDiadocCrypto.Create('Пустые данные для расшифровки');

  Store := OpenMyStore(UseLocalMachineStore);
  try
    FillChar(DecryptPara, SizeOf(DecryptPara), 0);
    DecryptPara.cbSize := SizeOf(DecryptPara);
    DecryptPara.dwMsgEncodingType := CERT_ENCODING;
    DecryptPara.cCertStore := 1;
    DecryptPara.rghCertStore := @Store;

    OutLen := 0;
    if not CryptDecryptMessage(@DecryptPara, @EncryptedContent[0], Length(EncryptedContent), nil, @OutLen, nil) then
    begin
      LastWin32 := GetLastError;
      if LastWin32 <> ERROR_MORE_DATA then
        RaiseOSError(LastWin32);
    end;

    SetLength(Result, OutLen);
    if not CryptDecryptMessage(@DecryptPara, @EncryptedContent[0], Length(EncryptedContent), @Result[0], @OutLen, nil) then
      RaiseLastOSError;
    SetLength(Result, OutLen);
  finally
    CloseStore(Store);
  end;
end;

function TDiadocWinCrypt.GetPersonalCertificates(OnlyWithPrivateKey: Boolean;
  UseLocalMachineStore: Boolean): TList<TBytes>;
var
  Store: HCERTSTORE;
  Ctx: PCCERT_CONTEXT;
  Err: DWORD;
  DER: TBytes;
begin
  Result := TList<TBytes>.Create;
  Store := OpenMyStore(UseLocalMachineStore);
  try
    Ctx := nil;
    repeat
      Ctx := CertEnumCertificatesInStore(Store, Ctx);
      if Ctx = nil then
      begin
        Err := GetLastError;
        if (Err = DWORD($80092004)) or (Err = ERROR_NO_MORE_FILES) then
          Break;
        if Err <> 0 then
          RaiseOSError(Err);
        Break;
      end;
      if (not OnlyWithPrivateKey) or HasPrivateKey(Ctx) then
      begin
        SetLength(DER, Ctx^.cbCertEncoded);
        Move(Ctx^.pbCertEncoded^, DER[0], Ctx^.cbCertEncoded);
        Result.Add(DER);
      end;
    until False;
  finally
    CloseStore(Store);
  end;
end;

function ThumbprintMatches(const CertDER: TBytes; const ThumbprintHex: string): Boolean;
var
  Ctx: PCCERT_CONTEXT;
  Sz: DWORD;
  Prop: TBytes;
  I: Integer;
  Hex: string;
begin
  Result := False;
  Ctx := CertCreateCertificateContext(CERT_ENCODING or PKCS_7_ASN_ENCODING, @CertDER[0], Length(CertDER));
  if Ctx = nil then
    Exit;
  try
    Sz := 0;
    if not CertGetCertificateContextProperty(Ctx, CERT_SHA1_HASH_PROP_ID, nil, Sz) then
      Exit;
    SetLength(Prop, Sz);
    if not CertGetCertificateContextProperty(Ctx, CERT_SHA1_HASH_PROP_ID, @Prop[0], Sz) then
      Exit;
    Hex := '';
    for I := 0 to Length(Prop) - 1 do
      Hex := Hex + IntToHex(Prop[I], 2);
    Result := SameText(StringReplace(ThumbprintHex, ' ', '', [rfReplaceAll]), Hex);
  finally
    CertFreeCertificateContext(Ctx);
  end;
end;

function TDiadocWinCrypt.GetCertificateWithPrivateKey(const ThumbprintHex: string;
  UseLocalMachineStore: Boolean): TBytes;
var
  List: TList<TBytes>;
  I: Integer;
begin
  List := GetPersonalCertificates(True, UseLocalMachineStore);
  try
    for I := 0 to List.Count - 1 do
      if ThumbprintMatches(List[I], ThumbprintHex) then
        Exit(List[I]);
    raise EDiadocCrypto.Create('Не найден сертификат с закрытым ключом и отпечатком ' + ThumbprintHex);
  finally
    List.Free;
  end;
end;

{$ELSE}

implementation

{ Заглушка для не-Windows: модуль не используется }

{$ENDIF MSWINDOWS}

end.

