//! TPM Library Part 2 Chapter 6 - Constants
//!
//! Module description ... TODO

use crate::tpm2::errors;
use crate::tpm2::serialization::inout::{RwBytes, Tpm2StructIn, Tpm2StructOut};

use std::convert::TryFrom;
use std::{fmt,result};

/// TPM_ST
#[derive(Clone, Copy, Default, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum TpmSt {
    RspCommand = 0x00c4,
    #[default]
    Null = 0x8000,
    NoSessions = 0x8001,
    Sessions = 0x8002,
    AttestNv = 0x8014,
    AttestCommandAudit = 0x8015,
    AttestSessionAudit = 0x8016,
    AttestCertify = 0x8017,
    AttestQuote = 0x8018,
    AttestTime = 0x8019,
    AttestCreation = 0x801a,
    Attest_nvDigest = 0x801c,
    Creation = 0x8021,
    Verified = 0x8022,
    AuthSecret = 0x8023,
    HashCheck = 0x8024,
    AuthSigned = 0x8025,
    FuManifest = 0x8029,
}

impl Tpm2StructOut for TpmSt {
    fn pack(&self, buff: &mut dyn RwBytes) {
        buff.write_bytes(&(*self as u16).to_be_bytes()[..]);
    }
}

impl Tpm2StructIn for TpmSt {
    fn unpack(
        &mut self,
        buff: &mut dyn RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        let byte_array = <[u8; size_of!(TpmSt)]>::try_from(&buff.read_bytes(size_of!(TpmSt))[..]);
        match byte_array {
            Ok(byte_array) => {
                *self = match u16::from_be_bytes(byte_array) {
                    a if a == TpmSt::RspCommand as u16 => Self::RspCommand,
                    a if a == TpmSt::Null as u16 => Self::Null,
                    a if a == TpmSt::NoSessions as u16 => Self::NoSessions,
                    a if a == TpmSt::Sessions as u16 => Self::Sessions,
                    a if a == TpmSt::AttestNv as u16 => Self::AttestNv,
                    a if a == TpmSt::AttestCommandAudit as u16 => Self::AttestCommandAudit,
                    a if a == TpmSt::AttestSessionAudit as u16 => Self::AttestSessionAudit,
                    a if a == TpmSt::AttestCertify as u16 => Self::AttestCertify,
                    a if a == TpmSt::AttestQuote as u16 => Self::AttestQuote,
                    a if a == TpmSt::AttestTime as u16 => Self::AttestTime,
                    a if a == TpmSt::AttestCreation as u16 => Self::AttestCreation,
                    a if a == TpmSt::Attest_nvDigest as u16 => Self::Attest_nvDigest,
                    a if a == TpmSt::Creation as u16 => Self::Creation,
                    a if a == TpmSt::Verified as u16 => Self::Verified,
                    a if a == TpmSt::AuthSecret as u16 => Self::AuthSecret,
                    a if a == TpmSt::HashCheck as u16 => Self::HashCheck,
                    a if a == TpmSt::AuthSigned as u16 => Self::AuthSigned,
                    a if a == TpmSt::FuManifest as u16 => Self::FuManifest,
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

impl fmt::Display for TpmSt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &(*self as u16))
    }
}
