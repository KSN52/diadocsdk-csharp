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
    function ResolveHashOidByCertificate(const ACertContext: PCERT_CONTEXT): AnsiString;
    function HasPrivateKey(const ACertContext: PCERT_CONTEXT): Boolean;
    function ReadCertificateHash(const ACertContext: PCERT_CONTEXT): TBytes;
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
  CryptoKit.CryptApi,
  CryptoKit.Bytes,
  CryptoKit.CertificateUtils,
  CryptoKit.Exceptions,
  CryptoKit.Utils;

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

function CertDuplicateOrError(const ACertContext: PCERT_CONTEXT): PCERT_CONTEXT;
begin
  Result := CertDuplicateCertificateContext(ACertContext);
  if Result = nil then
    RaiseLastOSError;
end;

function TCryptoSignatureService.ResolveHashOidByCertificate(
  const ACertContext: PCERT_CONTEXT
): AnsiString;
begin
  Result := CryptoKit.CertificateUtils.ResolveHashOidBySignatureOid(
    GetCertificateSignatureAlgorithmOid(ACertContext)
  );
end;

function TCryptoSignatureService.HasPrivateKey(
  const ACertContext: PCERT_CONTEXT
): Boolean;
begin
  Result := CryptoKit.CertificateUtils.HasPrivateKey(ACertContext);
end;

function TCryptoSignatureService.ReadCertificateHash(
  const ACertContext: PCERT_CONTEXT
): TBytes;
begin
  Result := CryptoKit.CertificateUtils.ReadCertificateHash(ACertContext);
end;

function TCryptoSignatureService.ReadCertificateEncoded(
  const ACertContext: PCERT_CONTEXT
): TBytes;
begin
  Result := CryptoKit.CertificateUtils.ReadCertificateEncoded(ACertContext);
end;

function TCryptoSignatureService.BuildCertificateInfo(
  const ACertContext: PCERT_CONTEXT
): TCryptoCertificate;
begin
  Result := CryptoKit.CertificateUtils.BuildCertificateInfo(
    ACertContext,
    HasPrivateKey(ACertContext)
  );
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
          if HasPrivateKey(CertContext) and EqualBytes(ReadCertificateHash(CertContext), ACertificateHash) then
          begin
            Result := CertDuplicateOrError(CertContext);
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
      Result := CertDuplicateOrError(InitialCert);
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
