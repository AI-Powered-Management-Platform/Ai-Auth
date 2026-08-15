// Hand-written wrapper over buf-generated code. The generated files carry
// their own allow-attributes; the blanket allow here keeps `clippy -D
// warnings` aimed at OUR code, not the generator's style.
#[allow(clippy::all, clippy::pedantic)]
pub mod aiauth {
    pub mod crypto {
        pub mod v1 {
            // The prost file include!s its .tonic.rs sibling itself.
            include!("aiauth/crypto/v1/aiauth.crypto.v1.rs");
        }
    }
}
