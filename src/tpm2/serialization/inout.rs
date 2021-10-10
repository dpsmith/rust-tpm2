use crate::tpm2::errors;
use bytebuffer::ByteBuffer;
use std::convert::TryFrom;
use std::result;

// Tpm2StructOut is a trait for TPM objects which can be serialized in
// big endian stream for TPM operations
pub trait Tpm2StructOut {
    fn pack(&self, buff: &mut ByteBuffer);
}

// Tpm2StructIn is a trait for TPM objects which can be deserialized from
// a byte stream
pub trait Tpm2StructIn {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError>;
}

// impl_tpm2_io is a macro which implments Tpm2StructIn and Tpm2StructOut for
// primitive numeric types. Primitive types have copy semantics, everything else
// has move semantics
macro_rules! impl_tpm2_io {
    ($T: ident) => {
        impl Tpm2StructOut for $T {
            fn pack(&self, buff: &mut ByteBuffer) {
                buff.write_bytes(&self.to_be_bytes()[..]);
            }
        }

        impl Tpm2StructIn for $T {
            fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
                let byte_array = <[u8; size_of!($T)]>::try_from(&buff.read_bytes(size_of!($T))[..]);
                match byte_array {
                    Ok(byte_array) => {
                        *self = $T::from_be_bytes(byte_array);
                        Ok(())
                    }
                    Err(_) => Err(errors::TpmError {
                        msg: String::from("could not prepare byteArray"),
                    }),
                }
            }
        }
    };
}

impl_tpm2_io! { u8 }
impl_tpm2_io! { u16 }
impl_tpm2_io! { u32 }
impl_tpm2_io! { u64 }

// normally belong to Command/Response structures
pub fn pack(fields: &[impl Tpm2StructOut], buff: &mut ByteBuffer) {
    for field in fields.iter() {
        field.pack(buff)
    }
}
