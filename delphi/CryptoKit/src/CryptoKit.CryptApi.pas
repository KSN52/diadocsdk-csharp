unit CryptoKit.CryptApi;

interface

uses
  Winapi.Windows;

type
  PPCERT_CONTEXT = ^PCERT_CONTEXT;
  PPBYTE = ^PByte;
  PDWORD = ^DWORD;
  PCERT_CONTEXT = ^CERT_CONTEXT;

  CRYPT_DATA_BLOB = packed record
    cbData: DWORD;
    pbData: PByte;
  end;

  CRYPT_ALGORITHM_IDENTIFIER = packed record
    pszObjId: PAnsiChar;
    Parameters: CRYPT_DATA_BLOB;
  end;

  CRYPT_SIGN_MESSAGE_PARA = packed record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    pSigningCert: PCERT_CONTEXT;
    HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    pvHashAuxInfo: Pointer;
    cMsgCert: DWORD;
    rgpMsgCert: PPCERT_CONTEXT;
    cMsgCrl: DWORD;
    rgpMsgCrl: Pointer;
    cAuthAttr: DWORD;
    rgAuthAttr: Pointer;
    cUnauthAttr: DWORD;
    rgUnauthAttr: Pointer;
    dwFlags: DWORD;
    dwInnerContentType: DWORD;
    HashEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    pvHashEncryptionAuxInfo: Pointer;
  end;

  CRYPT_VERIFY_MESSAGE_PARA = packed record
    cbSize: DWORD;
    dwMsgAndCertEncodingType: DWORD;
    hCryptProv: NativeUInt;
    pfnGetSignerCertificate: Pointer;
    pvGetArg: Pointer;
  end;

  CERT_CONTEXT = packed record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: Pointer;
    hCertStore: Pointer;
  end;

const
  X509_ASN_ENCODING = DWORD($00000001);
  PKCS_7_ASN_ENCODING = DWORD($00010000);
  ENCODING = X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;

  CERT_KEY_PROV_INFO_PROP_ID = 2;
  CERT_HASH_PROP_ID = 3;
  CERT_STORE_PROV_SYSTEM = 10;
  CERT_STORE_NAME_MY = 'MY';
  CERT_STORE_NAME_ROOT = 'ROOT';
  CERT_STORE_NAME_CA = 'CA';
  CERT_STORE_NAME_ADDRESSBOOK = 'AddressBook';
  CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
  CERT_NAME_ISSUER_FLAG = 1;

  CERT_STORE_OPEN_EXISTING_FLAG = DWORD($00004000);
  CERT_STORE_READONLY_FLAG = DWORD($00008000);
  CERT_SYSTEM_STORE_CURRENT_USER = DWORD($00010000);
  CERT_SYSTEM_STORE_LOCAL_MACHINE = DWORD($00020000);

  ERROR_NO_MORE_FILES = 18;
  CRYPT_E_NOT_FOUND = HRESULT($80092004);
  CRYPT_E_NO_SIGNER = HRESULT($8009200E);
  NTE_BAD_SIGNATURE = HRESULT($80090006);

  OID_GOST_34_11_94 = '1.2.643.2.2.9';
  OID_GOST_34_11_12_256 = '1.2.643.7.1.1.2.2';
  OID_GOST_34_11_12_512 = '1.2.643.7.1.1.2.3';
  OID_GOST_34_11_94_R3410EL = '1.2.643.2.2.3';
  OID_GOST_34_11_12_256_R3410 = '1.2.643.7.1.1.3.2';
  OID_GOST_34_11_12_512_R3410 = '1.2.643.7.1.1.3.3';

function CryptSignMessage(
  var pSignPara: CRYPT_SIGN_MESSAGE_PARA;
  fDetachedSignature: BOOL;
  cToBeSigned: DWORD;
  rgpbToBeSigned: PPBYTE;
  rgcbToBeSigned: PDWORD;
  pbSignedBlob: PByte;
  var pcbSignedBlob: DWORD
): BOOL; stdcall; external 'crypt32.dll';

function CryptVerifyDetachedMessageSignature(
  var pVerifyPara: CRYPT_VERIFY_MESSAGE_PARA;
  dwSignerIndex: DWORD;
  pbDetachedSignBlob: PByte;
  cbDetachedSignBlob: DWORD;
  cToBeVerified: DWORD;
  rgpbToBeVerified: PPBYTE;
  rgcbToBeVerified: PDWORD;
  out ppSignerCert: PCERT_CONTEXT
): BOOL; stdcall; external 'crypt32.dll';

function CertOpenStore(
  lpszStoreProvider: Pointer;
  dwEncodingType: DWORD;
  hCryptProv: NativeUInt;
  dwFlags: DWORD;
  pvPara: Pointer
): Pointer; stdcall; external 'crypt32.dll';

function CertCloseStore(hCertStore: Pointer; dwFlags: DWORD): BOOL; stdcall; external 'crypt32.dll';

function CertEnumCertificatesInStore(hCertStore: Pointer; pPrevCertContext: PCERT_CONTEXT): PCERT_CONTEXT; stdcall; external 'crypt32.dll';

function CertDuplicateCertificateContext(pCertContext: PCERT_CONTEXT): PCERT_CONTEXT; stdcall; external 'crypt32.dll';

function CertFreeCertificateContext(pCertContext: PCERT_CONTEXT): BOOL; stdcall; external 'crypt32.dll';

function CertGetCertificateContextProperty(
  pCertContext: PCERT_CONTEXT;
  dwPropId: DWORD;
  pvData: Pointer;
  var pcbData: DWORD
): BOOL; stdcall; external 'crypt32.dll';

function CertCreateCertificateContext(
  dwCertEncodingType: DWORD;
  pbCertEncoded: PByte;
  cbCertEncoded: DWORD
): PCERT_CONTEXT; stdcall; external 'crypt32.dll';

function CertGetNameStringW(
  pCertContext: PCERT_CONTEXT;
  dwType: DWORD;
  dwFlags: DWORD;
  pvTypePara: Pointer;
  pszNameString: PWideChar;
  cchNameString: DWORD
): DWORD; stdcall; external 'crypt32.dll';

implementation

end.
