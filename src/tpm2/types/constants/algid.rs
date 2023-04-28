//! TPM Library Part 2 Chapter 6 - Constants
//!
//! Module description ... TODO

use crate::tpm2::errors;
use crate::tpm2::serialization::inout::{RwBytes, Tpm2StructIn, Tpm2StructOut};

use std::convert::TryFrom;
use std::{fmt,result};

/// TPM_ALG_ID
#[derive(Clone, Copy, Default, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum TpmAlgId {
    #[default]
	Error = 0x0000,
	RSA = 0x0001,
	TDES = 0x0003,
	SHA1 = 0x0004,
	HMAC = 0x0005,
	AES = 0x0006,
	MGF1 = 0x0007,
	KeyedHash = 0x0008,
	XOR = 0x000A,
	SHA256 = 0x000B,
	SHA384 = 0x000C,
	SHA512 = 0x000D,
	Null = 0x0010,
	SM3_256 = 0x0012,
	SM4 = 0x0013,
	RSASSA = 0x0014,
	RSAES = 0x0015,
	RSAPSS = 0x0016,
	OAEP = 0x0017,
	ECDH = 0x0019,
	ECDAA = 0x001A,
	SM2 = 0x001B,
	ECSCHNORR = 0x001C,
	ECMQV = 0x001D,
	KDF1_SP800_56A = 0x0020,
	KDF2 = 0x0021,
	KDF1_SP800_108 = 0x0022,
	ECC = 0x0023,
	SymCipher = 0x0025,
	Camellia = 0x0026,
	SHA3_256 = 0x0027,
	SHA3_384 = 0x0028,
	SHA3_512 = 0x0029,
	CTR = 0x0040,
	OFB = 0x0041,
	CBC = 0x0042,
	CFB = 0x0043,
	ECB = 0x0044,
}

impl Tpm2StructOut for TpmAlgId {
    fn pack(&self, buff: &mut dyn RwBytes) {
        buff.write_bytes(&(*self as u16).to_be_bytes()[..]);
    }
}

impl Tpm2StructIn for TpmAlgId {
    fn unpack(
        &mut self,
        buff: &mut dyn RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        let byte_array = <[u8; size_of!(TpmAlgId)]>::try_from(&buff.read_bytes(size_of!(TpmAlgId))[..]);
        match byte_array {
            Ok(byte_array) => {
                *self = match u16::from_be_bytes(byte_array) {
                    0x0000 => Self::Error,
                    0x0001 => Self::RSA,
                    0x0003 => Self::TDES,
                    0x0004 => Self::SHA1,
                    0x0005 => Self::HMAC,
                    0x0006 => Self::AES,
                    0x0007 => Self::MGF1,
                    0x0008 => Self::KeyedHash,
                    0x000A => Self::XOR,
                    0x000B => Self::SHA256,
                    0x000C => Self::SHA384,
                    0x000D => Self::SHA512,
                    0x0010 => Self::Null,
                    0x0012 => Self::SM3_256,
                    0x0013 => Self::SM4,
                    0x0014 => Self::RSASSA,
                    0x0015 => Self::RSAES,
                    0x0016 => Self::RSAPSS,
                    0x0017 => Self::OAEP,
                    0x0019 => Self::ECDH,
                    0x001A => Self::ECDAA,
                    0x001B => Self::SM2,
                    0x001C => Self::ECSCHNORR,
                    0x001D => Self::ECMQV,
                    0x0020 => Self::KDF1_SP800_56A,
                    0x0021 => Self::KDF2,
                    0x0022 => Self::KDF1_SP800_108,
                    0x0023 => Self::ECC,
                    0x0025 => Self::SymCipher,
                    0x0026 => Self::Camellia,
                    0x0027 => Self::SHA3_256,
                    0x0028 => Self::SHA3_384,
                    0x0029 => Self::SHA3_512,
                    0x0040 => Self::CTR,
                    0x0041 => Self::OFB,
                    0x0042 => Self::CBC,
                    0x0043 => Self::CFB,
                    0x0044 => Self::ECB,
                    _ => return Err(errors::DeserializationError {
                        msg: String::from("could not prepare byteArray"),
                    }),
                };
                Ok(())
            }
            Err(_) => Err(errors::DeserializationError {
                msg: String::from("could not prepare byteArray"),
            }),
        }
    }
}

impl fmt::Display for TpmAlgId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &(*self as u16))
    }
}
