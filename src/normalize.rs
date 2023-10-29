use std::mem;

pub(crate) fn replace_symbols(password: &mut String) {
    let mut bytes = mem::take(password).into_bytes();
    for byte in bytes.iter_mut() {
        *byte = match byte {
            b'0' => b'o',
            b'1' => b'l',
            b'2' => b'z',
            b'3' => b'e',
            b'4' => b'a',
            b'5' => b's',
            b'6' => b'g',
            b'7' => b't',
            b'8' => b'b',
            b'9' => b'q',
            b'!' => b'i',
            b'@' => b'a',
            b'#' => b'h',
            b'$' => b's',
            b'%' => b'z',
            &mut b => b
        };
    }

    *password = String::from_utf8(bytes).expect("Invalid UTF-8");
}