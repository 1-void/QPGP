use encrypto_core::EncryptoError;

#[test]
fn error_display_messages() {
    let err = EncryptoError::not_implemented("feature");
    assert_eq!(err.to_string(), "not implemented: feature");

    let err = EncryptoError::InvalidInput("bad input".into());
    assert_eq!(err.to_string(), "invalid input: bad input");

    let err = EncryptoError::Backend("oops".into());
    assert_eq!(err.to_string(), "backend error: oops");

    let err = EncryptoError::Io("disk".into());
    assert_eq!(err.to_string(), "io error: disk");
}
