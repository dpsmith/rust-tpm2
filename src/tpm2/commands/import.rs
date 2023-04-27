use crate::device;
use crate::tpm2::commands::{load, run, session, unseal};
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::{RwBytes, Tpm2StructIn, Tpm2StructOut};
use crate::tpm2::types::tcg;

use std::result;

use pem::parse;
use rsa;
use rsa::pkcs8::DecodePublicKey;

const SAMPLE: &'static str = "
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt75GjDKVXgtzPtVIxiiR
4bTGY9DKCwjIptkdWr6M1BqqfK3TVcA7BKK1nIZ/pYwRV/fJjshVbJbkBWJ8OHm2
LnF/nIOYvhN5fT28DBZbu9BIMKJ7+FoI/FnnXgLh3Z17EBhssP5Xytg6alxHrH6z
0+VyB4z/lqE2XHHbqFb44JWG0IixbAn7Za9P2GgIpB004y1nsXG08rlz0cMU0nE2
3+AWM0TsHtFE1Byg3x/gpkeV4lnEq1luBiCInXnK6TfYSno8gXKSX5Y2+bJ5NBaU
vy6TEEf6dU5SDjSDBGagtlX8juQpdcuN/L+0MkZ1Gqj6hdYBGl4eFlc5DKokncPv
0QIDAQAB
-----END PUBLIC KEY-----";

pub fn tpm2_import(
    tpm: &mut dyn device::raw::TpmDeviceOps,
    parent_handle: tcg::Handle,
    auth: tcg::TpmsAuthCommand,
) -> result::Result<tcg::Tpm2bData, errors::CommandError> {
    println!("importing with parent_handle {:02x?}", parent_handle);

    let pem_result = parse(SAMPLE);
    match pem_result {
        Ok(_) => (),
        Err(_) => panic!("pem error"),
    }
    let pem = pem_result.unwrap();
    println!("{}", pem.tag());

    let public_key_result = rsa::RsaPublicKey::from_public_key_pem(SAMPLE);
    match public_key_result {
        Ok(_) => (),
        Err(_) => panic!("pem error"),
    }
    let public_key = public_key_result.unwrap();

    let secret = "secret data";

    // Create TpmtSensitive, based on the secret provided. This will be used
    // for the creation of `duplicate`.
    let sensitive = tcg::TpmtSensitive::new(secret.as_bytes());

    // Create the TPMT_PUBLIC from the sensitive object
    let public = tcg::TpmtPublic::new_data_object(&sensitive);

    tcg::kdfa(
        &[
            0xda, 0x82, 0xeb, 0x71, 0xb1, 0x8c, 0xb9, 0xae, 0xfc, 0x9c, 0x88, 0xa5, 0xff, 0x03,
            0x01, 0x6f, 0x12, 0xd1, 0x74, 0x0b, 0x05, 0x78, 0x21, 0xcd, 0xff, 0x9e, 0xac, 0xba,
            0xb7, 0xbd, 0xd3, 0xc9,
        ],
        "STORAGE".as_bytes(),
        &[
            0x00, 0x0b, 0x8c, 0xca, 0x34, 0xd8, 0xb9, 0xf4, 0xae, 0xbe, 0xe7, 0x91, 0xf8, 0xd0,
            0xa4, 0xdf, 0xcf, 0xc2, 0x2f, 0x20, 0x87, 0xc1, 0xc9, 0xfa, 0x4c, 0x79, 0xb5, 0xa0,
            0x8b, 0x27, 0xcf, 0x8a, 0xd6, 0x59,
        ],
        &[],
        128,
    );

    let mut enc_seed: tcg::Tpm2bEncryptedSecret = tcg::Tpm2bEncryptedSecret::new();

    // Create the duplicate (TPM2B_PRIVATE) object based on the sensitive content
    let duplicate = tcg::Tpm2bPrivate::new_duplicate(&public_key, sensitive, public, &mut enc_seed);

    let mut buff_public = inout::StaticByteBuffer::new();
    public.pack(&mut buff_public);

    let mut resp_buff = inout::StaticByteBuffer::new();

    let handles: [tcg::Handle; 1] = [parent_handle];
    let auths: [tcg::TpmsAuthCommand; 1] = [auth];

    let params: [&dyn inout::Tpm2StructOut; 5] = [
        &tcg::Tpm2bData {
            size: 0,
            buffer: [0; 1024],
        },
        &tcg::Tpm2bPublic {
            size: buff_public.to_bytes().len() as u16,
            public: public,
        },
        &duplicate,
        &enc_seed,
        &tcg::TpmtSymDefObject::new_null(),
    ];

    run::run_command(
        tpm,
        tcg::TPM_CC_IMPORT,
        &handles,
        &auths,
        &params,
        &mut resp_buff,
    )?;

    let mut param_size: u32 = 0;
    param_size.unpack(&mut resp_buff)?;

    let mut out_private: tcg::Tpm2bPrivate = tcg::Tpm2bPrivate::new();
    out_private.unpack(&mut resp_buff)?;

    session::tpm2_policy_secret(tpm, 0x4000000B, auth)?;

    let loaded_handle = load::tpm2_load(
        tpm,
        parent_handle,
        auth,
        out_private,
        tcg::Tpm2bPublic {
            size: buff_public.to_bytes().len() as u16,
            public: public,
        },
    )?;

    // This is unnecessary. Just use emptyAuth
    session::tpm2_startauth_session(tpm)?;

    let data = unseal::tpm2_unseal(tpm, loaded_handle)?;
    Ok(data)
}
