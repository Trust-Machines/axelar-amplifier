#[macro_export]
macro_rules! impl_stacks_message_codec_for_int {
    ($typ:ty; $array:expr) => {
        impl StacksMessageCodec for $typ {
            fn consensus_serialize<W: Write>(
                &self,
                fd: &mut W,
            ) -> Result<(), $crate::common::codec::Error> {
                fd.write_all(&self.to_be_bytes())
                    .map_err($crate::common::codec::Error::WriteError)
            }
        }
    };
}
