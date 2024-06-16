pub(crate) fn replace_symbols(password: &mut str) {
    // SAFETY: All operations are only in-place transforming single-byte UTF-8 codepoints.
    // For this reason, any multi-byte codepoints will remain untouched.
    let bytes = unsafe { password.as_bytes_mut() };

    bytes.iter_mut().for_each(|byte| {
        *byte = match byte {
            b'!' => b'i',
            b'@' => b'a',
            b'#' => b'h',
            b'$' => b's',
            b'%' => b'z',
            &mut b => b
        };
    });
}
