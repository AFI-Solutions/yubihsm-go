package commands

import (
	"fmt"
)

func (c CommandType) String() string {
	switch c {
	case CommandTypeEcho:
		return "Echo"
	case CommandTypeCreateSession:
		return "CreateSession"
	case CommandTypeAuthenticateSession:
		return "AuthenticateSession"
	case CommandTypeSessionMessage:
		return "SessionMessage"
	case CommandTypeDeviceInfo:
		return "DeviceInfo"
	case CommandTypeReset:
		return "Reset"
	case CommandTypeCloseSession:
		return "CloseSession"
	case CommandTypeStorageStatus:
		return "StorageStatus"
	case CommandTypePutOpaque:
		return "PutOpaque"
	case CommandTypeGetOpaque:
		return "GetOpaque"
	case CommandTypePutAuthKey:
		return "PutAuthKey"
	case CommandTypePutAsymmetric:
		return "PutAsymmetric"
	case CommandTypeGenerateAsymmetricKey:
		return "GenerateAsymmetricKey"
	case CommandTypeSignDataPkcs1:
		return "SignDataPkcs1"
	case CommandTypeListObjects:
		return "ListObjects"
	case CommandTypeDecryptPkcs1:
		return "DecryptPkcs1"
	case CommandTypeExportWrapped:
		return "ExportWrapped"
	case CommandTypeImportWrapped:
		return "ImportWrapped"
	case CommandTypePutWrapKey:
		return "PutWrapKey"
	case CommandTypeGetLogs:
		return "GetLogs"
	case CommandTypeGetObjectInfo:
		return "GetObjectInfo"
	case CommandTypePutOption:
		return "PutOption"
	case CommandTypeGetOption:
		return "GetOption"
	case CommandTypeGetPseudoRandom:
		return "GetPseudoRandom"
	case CommandTypePutHMACKey:
		return "PutHMACKey"
	case CommandTypeHMACData:
		return "HMACData"
	case CommandTypeGetPubKey:
		return "GetPubKey"
	case CommandTypeSignDataPss:
		return "SignDataPss"
	case CommandTypeSignDataEcdsa:
		return "SignDataEcdsa"
	case CommandTypeDecryptEcdh:
		return "DecryptEcdh"
	case CommandTypeDeleteObject:
		return "DeleteObject"
	case CommandTypeDecryptOaep:
		return "DecryptOaep"
	case CommandTypeGenerateHMACKey:
		return "GenerateHMACKey"
	case CommandTypeGenerateWrapKey:
		return "GenerateWrapKey"
	case CommandTypeVerifyHMAC:
		return "VerifyHMAC"
	case CommandTypeOTPDecrypt:
		return "OTPDecrypt"
	case CommandTypeOTPAeadCreate:
		return "OTPAeadCreate"
	case CommandTypeOTPAeadRandom:
		return "OTPAeadRandom"
	case CommandTypeOTPAeadRewrap:
		return "OTPAeadRewrap"
	case CommandTypeAttestAsymmetric:
		return "AttestAsymmetric"
	case CommandTypePutOTPAeadKey:
		return "PutOTPAeadKey"
	case CommandTypeGenerateOTPAeadKey:
		return "GenerateOTPAeadKey"
	case CommandTypeSetLogIndex:
		return "SetLogIndex"
	case CommandTypeWrapData:
		return "WrapData"
	case CommandTypeUnwrapData:
		return "UnwrapData"
	case CommandTypeSignDataEddsa:
		return "SignDataEddsa"
	case CommandTypeSetBlink:
		return "SetBlink"
	case CommandTypeChangeAuthenticationKey:
		return "ChangeAuthenticationKey"
	default:
		return fmt.Sprintf("%02x", int(c))
	}
}

func (e ErrorCode) String() string {
	switch e {
	case ErrorCodeOK:
		return "OK"
	case ErrorCodeInvalidCommand:
		return "InvalidCommand"
	case ErrorCodeInvalidData:
		return "InvalidData"
	case ErrorCodeInvalidSession:
		return "InvalidSession"
	case ErrorCodeAuthFail:
		return "AuthFail"
	case ErrorCodeSessionFull:
		return "SessionFull"
	case ErrorCodeSessionFailed:
		return "SessionFailed"
	case ErrorCodeStorageFailed:
		return "StorageFailed"
	case ErrorCodeWrongLength:
		return "WrongLength"
	case ErrorCodeInvalidPermission:
		return "InvalidPermission"
	case ErrorCodeLogFull:
		return "LogFull"
	case ErrorCodeObjectNotFound:
		return "ObjectNotFound"
	case ErrorCodeInvalidID:
		return "InvalidID"
	case ErrorCodeCommandUnexecuted:
		return "CommandUnexecuted"
	default:
		return fmt.Sprintf("%02x", int(e))
	}
}

func (a Algorithm) String() string {
	switch a {
	case AlgorithmRSAPKCS1SHA1:
		return "RSAPKCS1SHA1"
	case AlgorithmRSAPKCS1SHA256:
		return "RSAPKCS1SHA256"
	case AlgorithmRSAPKCS1SHA384:
		return "RSAPKCS1SHA384"
	case AlgorithmRSAPKCS1SHA512:
		return "RSAPKCS1SHA512"
	case AlgorithmRSAPSSSHA1:
		return "RSAPSSSHA1"
	case AlgorithmRSAPSSSHA256:
		return "RSAPSSSHA256"
	case AlgorithmRSAPSSSHA384:
		return "RSAPSSSHA384"
	case AlgorithmRSAPSSSHA512:
		return "RSAPSSSHA512"
	case AlgorithmRSA2048:
		return "RSA2048"
	case AlgorithmRSA3072:
		return "RSA3072"
	case AlgorithmRSA4096:
		return "RSA4096"
	case AlgorithmP256:
		return "P256"
	case AlgorithmP384:
		return "P384"
	case AlgorithmP521:
		return "P521"
	case AlgorithmSecp256k1:
		return "Secp256k1"
	case AlgorithmOpaqueData:
		return "OpaqueData"
	case AlgorithmOpaqueX509Certificate:
		return "OpaqueX509Certificate"
	case AlgorithmYubicoAESAuthentication:
		return "YubicoAESAuthentication"
	case AlgorithmAES128CCMWrap:
		return "AES128CCMWrap"
	case AlgorithmAES192CCMWrap:
		return "AES192CCMWrap"
	case AlgorithmAES256CCMWrap:
		return "AES256CCMWrap"
	case AlgorithmECDSASHA256:
		return "ECDSASHA256"
	case AlgorithmECDSASHA384:
		return "ECDSASHA384"
	case AlgorithmECDSASHA512:
		return "ECDSASHA512"
	case AlgorithmED25519:
		return "ED25519"
	case AlgorithmECP224:
		return "ECP224"
	default:
		return fmt.Sprintf("%02x", int(a))
	}
}
