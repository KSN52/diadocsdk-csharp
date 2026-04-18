unit CryptoKit.SignatureService;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  CryptoKit.Types,
  CryptoKit.Interfaces,
  CryptoKit.BaseService;

type
  TCryptoSignatureService = class(TCryptoServiceBase, ICryptoSignatureService)
  private
    function ResolveHashOidBySignatureOid(const ASignatureOid: string): AnsiString;
    function ResolveHashOidByCertificate(const ACertContext: PCERT_CONTEXT): AnsiString;
    function HasPrivateKey(const ACertContext: PCERT_CONTEXT): Boolean;
    function ReadCertificateHash(const ACertContext: PCERT_CONTEXT): TBytes;
    function ReadCertificateEncoded(const ACertContext: PCERT_CONTEXT): TBytes;
    function BuildCertificateInfo(const ACertContext: PCERT_CONTEXT): TCryptoCertificate;
    function OpenStore(
      const AStoreName: string;
      const AStoreLocationFlag: DWORD
    ): Pointer;
    function FindCertificateWithPrivateKeyByHash(
      const ACertificateHash: TBytes
    ): PCERT_CONTEXT;
    function ResolveSigningCertificate(const ACertificateEncoded: TBytes): PCERT_CONTEXT;
  public
    function SignDetached(
      const AContent, ACertificateEncoded: TBytes
    ): TBytes;
    function VerifyDetached(
      const AContent, ADetachedSignature: TBytes
    ): TCryptoCertificateArray;
  end;

implementation

uses
  System.AnsiStrings,
  Winapi.WinCrypt,
  CryptoKit.CryptApi,
  CryptoKit.Exceptions,
  CryptoKit.Encoding,
  CryptoKit.Utils;

function ByteArraysEqual(const ALeft, ARight: TBytes): Boolean;
var
  I: Integer;
begin
  if Length(ALeft) <> Length(ARight) then
    Exit(False);
  for I := 0 to Length(ALeft) - 1 do
  begin
    if ALeft[I] <> ARight[I] then
      Exit(False);
  end;
  Result := True;
end;

function GetCertificateName(
  const ACertContext: PCERT_CONTEXT;
  const AIsIssuer: Boolean
): string;
var
  NameFlags: DWORD;
  NameLen: DWORD;
begin
  if AIsIssuer then
    NameFlags := CERT_NAME_ISSUER_FLAG
  else
    NameFlags := 0;

  NameLen := CertGetNameStringW(
    ACertContext,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
    NameFlags,
    nil,
    nil,
    0
  );
  if NameLen <= 1 then
    Exit('');

  SetLength(Result, NameLen - 1);
  CertGetNameStringW(
    ACertContext,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
    NameFlags,
    nil,
    PWideChar(Result),
    NameLen
  );
end;

function StoreLocationFlags: TArray<DWORD>;
begin
  Result := TArray<DWORD>.Create(
    CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE
  );
end;

function StoreNames: TArray<string>;
begin
  Result := TArray<string>.Create(
    CERT_STORE_NAME_MY,
    CERT_STORE_NAME_ROOT,
    CERT_STORE_NAME_CA,
    CERT_STORE_NAME_ADDRESSBOOK
  );
end;

function TCryptoSignatureService.ResolveHashOidBySignatureOid(
  const ASignatureOid: string
): AnsiString;
begin
  if ASignatureOid = OID_GOST_34_11_94_R3410EL then
    Exit(AnsiString(OID_GOST_34_11_94));
  if ASignatureOid = OID_GOST_34_11_12_256_R3410 then
    Exit(AnsiString(OID_GOST_34_11_12_256));
  if ASignatureOid = OID_GOST_34_11_12_512_R3410 then
    Exit(AnsiString(OID_GOST_34_11_12_512));
  // Для non-GOST fallback на SHA-256.
  Result := AnsiString('2.16.840.1.101.3.4.2.1');
end;

function TCryptoSignatureService.ResolveHashOidByCertificate(
  const ACertContext: PCERT_CONTEXT
): AnsiString;
var
  CertInfo: PCERT_INFO;
  SignatureOid: string;
begin
  CertInfo := PCERT_INFO(ACertContext.pCertInfo);
  SignatureOid := string(AnsiString(CertInfo^.SignatureAlgorithm.pszObjId));
  Result := ResolveHashOidBySignatureOid(SignatureOid);
end;

function TCryptoSignatureService.HasPrivateKey(
  const ACertContext: PCERT_CONTEXT
): Boolean;
var
  DataLen: DWORD;
  LastErr: DWORD;
begin
  DataLen := 0;
  Result := CertGetCertificateContextProperty(
    ACertContext,
    CERT_KEY_PROV_INFO_PROP_ID,
    nil,
    DataLen
  );
  if Result then
    Exit(True);

  LastErr := GetLastError;
  if LastErr = DWORD(CRYPT_E_NOT_FOUND) then
    Exit(False);
  RaiseLastOSError(LastErr);
end;

function TCryptoSignatureService.ReadCertificateHash(
  const ACertContext: PCERT_CONTEXT
): TBytes;
var
  DataLen: DWORD;
begin
  DataLen := 0;
  if not CertGetCertificateContextProperty(
    ACertContext,
    CERT_HASH_PROP_ID,
    nil,
    DataLen
  ) then
    RaiseLastOSError;

  SetLength(Result, DataLen);
  if not CertGetCertificateContextProperty(
    ACertContext,
    CERT_HASH_PROP_ID,
    @Result[0],
    DataLen
  ) then
    RaiseLastOSError;
end;

function TCryptoSignatureService.ReadCertificateEncoded(
  const ACertContext: PCERT_CONTEXT
): TBytes;
begin
  SetLength(Result, ACertContext.cbCertEncoded);
  if ACertContext.cbCertEncoded > 0 then
    Move(ACertContext.pbCertEncoded^, Result[0], ACertContext.cbCertEncoded);
end;

function TCryptoSignatureService.BuildCertificateInfo(
  const ACertContext: PCERT_CONTEXT
): TCryptoCertificate;
begin
  Result.ThumbprintHex := BytesToHex(ReadCertificateHash(ACertContext));
  Result.SubjectName := GetCertificateName(ACertContext, False);
  Result.IssuerName := GetCertificateName(ACertContext, True);
  Result.HasPrivateKey := HasPrivateKey(ACertContext);
  Result.Encoded := ReadCertificateEncoded(ACertContext);
end;

function TCryptoSignatureService.OpenStore(
  const AStoreName: string;
  const AStoreLocationFlag: DWORD
): Pointer;
begin
  Result := CertOpenStore(
    Pointer(CERT_STORE_PROV_SYSTEM),
    0,
    0,
    AStoreLocationFlag or CERT_STORE_OPEN_EXISTING_FLAG or CERT_STORE_READONLY_FLAG,
    PWideChar(AStoreName)
  );
  if Result = nil then
    RaiseLastOSError;
end;

function TCryptoSignatureService.FindCertificateWithPrivateKeyByHash(
  const ACertificateHash: TBytes
): PCERT_CONTEXT;
var
  LocationFlag: DWORD;
  Name: string;
  StoreHandle: Pointer;
  CertContext: PCERT_CONTEXT;
begin
  Result := nil;
  for LocationFlag in StoreLocationFlags do
  begin
    for Name in StoreNames do
    begin
      StoreHandle := OpenStore(Name, LocationFlag);
      try
        CertContext := nil;
        while True do
        begin
          CertContext := CertEnumCertificatesInStore(StoreHandle, CertContext);
          if CertContext = nil then
          begin
            if GetLastError <> ERROR_NO_MORE_FILES then
              RaiseLastOSError;
            Break;
          end;
          if HasPrivateKey(CertContext) and ByteArraysEqual(ReadCertificateHash(CertContext), ACertificateHash) then
          begin
            Result := CertDuplicateCertificateContext(CertContext);
            Exit;
          end;
        end;
      finally
        CertCloseStore(StoreHandle, 0);
      end;
    end;
  end;
end;

function TCryptoSignatureService.ResolveSigningCertificate(
  const ACertificateEncoded: TBytes
): PCERT_CONTEXT;
var
  InitialCert: PCERT_CONTEXT;
  InitialHash: TBytes;
begin
  InitialCert := CertCreateCertificateContext(
    ENCODING,
    BytesPtr(ACertificateEncoded),
    Length(ACertificateEncoded)
  );
  if InitialCert = nil then
    RaiseLastOSError;

  try
    if HasPrivateKey(InitialCert) then
    begin
      Result := CertDuplicateCertificateContext(InitialCert);
      Exit;
    end;

    InitialHash := ReadCertificateHash(InitialCert);
    Result := FindCertificateWithPrivateKeyByHash(InitialHash);
    if Result = nil then
      raise ECryptoValidationError.Create('Certificate with private key not found');
  finally
    CertFreeCertificateContext(InitialCert);
  end;
end;

function TCryptoSignatureService.SignDetached(
  const AContent, ACertificateEncoded: TBytes
): TBytes;
var
  SignParams: CRYPT_SIGN_MESSAGE_PARA;
  SignCert: PCERT_CONTEXT;
  MsgCerts: array[0..0] of PCERT_CONTEXT;
  DataPtr: PByte;
  DataPtrArray: array[0..0] of PByte;
  DataLenArray: array[0..0] of DWORD;
  SignatureLen: DWORD;
  HashOid: AnsiString;
  HashOidBuffer: PAnsiChar;
begin
  RequireNotEmpty(ACertificateEncoded, 'Certificate bytes');
  SignCert := ResolveSigningCertificate(ACertificateEncoded);
  try
    HashOid := ResolveHashOidByCertificate(SignCert);
    FillChar(SignParams, SizeOf(SignParams), 0);
    SignParams.cbSize := SizeOf(SignParams);
    SignParams.dwMsgEncodingType := ENCODING;
    SignParams.pSigningCert := SignCert;
    HashOidBuffer := StrNew(PAnsiChar(HashOid));
    try
      SignParams.HashAlgorithm.pszObjId := HashOidBuffer;
      MsgCerts[0] := SignCert;
      SignParams.cMsgCert := 1;
      SignParams.rgpMsgCert := @MsgCerts[0];

      DataPtr := BytesPtr(AContent);
      DataPtrArray[0] := DataPtr;
      DataLenArray[0] := Length(AContent);

      SignatureLen := 0;
      if not CryptSignMessage(
        SignParams,
        True,
        1,
        @DataPtrArray[0],
        @DataLenArray[0],
        nil,
        SignatureLen
      ) then
        RaiseLastOSError;

      SetLength(Result, SignatureLen);
      if not CryptSignMessage(
        SignParams,
        True,
        1,
        @DataPtrArray[0],
        @DataLenArray[0],
        @Result[0],
        SignatureLen
      ) then
        RaiseLastOSError;
      SetLength(Result, SignatureLen);
    finally
      StrDispose(HashOidBuffer);
    end;
  finally
    CertFreeCertificateContext(SignCert);
  end;
end;

function TCryptoSignatureService.VerifyDetached(
  const AContent, ADetachedSignature: TBytes
): TCryptoCertificateArray;
var
  VerifyParams: CRYPT_VERIFY_MESSAGE_PARA;
  SignerIndex: DWORD;
  SignerCert: PCERT_CONTEXT;
  DataPtr: PByte;
  DataPtrArray: array[0..0] of PByte;
  DataLenArray: array[0..0] of DWORD;
  LastErr: DWORD;
  Items: TList<TCryptoCertificate>;
begin
  RequireNotEmpty(ADetachedSignature, 'Detached signature');

  FillChar(VerifyParams, SizeOf(VerifyParams), 0);
  VerifyParams.cbSize := SizeOf(VerifyParams);
  VerifyParams.dwMsgAndCertEncodingType := ENCODING;

  DataPtr := BytesPtr(AContent);
  DataPtrArray[0] := DataPtr;
  DataLenArray[0] := Length(AContent);

  Items := TList<TCryptoCertificate>.Create;
  try
    SignerIndex := 0;
    while True do
    begin
      SignerCert := nil;
      if not CryptVerifyDetachedMessageSignature(
        VerifyParams,
        SignerIndex,
        BytesPtr(ADetachedSignature),
        Length(ADetachedSignature),
        1,
        @DataPtrArray[0],
        @DataLenArray[0],
        SignerCert
      ) then
      begin
        LastErr := GetLastError;
        if LastErr = DWORD(CRYPT_E_NO_SIGNER) then
          Break;
        if LastErr = ERROR_NO_MORE_FILES then
          Break;
        if LastErr = DWORD(NTE_BAD_SIGNATURE) then
          raise ECryptoValidationError.Create('Invalid detached signature');
        RaiseLastOSError(LastErr);
      end;

      try
        Items.Add(BuildCertificateInfo(SignerCert));
      finally
        CertFreeCertificateContext(SignerCert);
      end;
      Inc(SignerIndex);
    end;

    Result := Items.ToArray;
  finally
    Items.Free;
  end;
end;

end.
