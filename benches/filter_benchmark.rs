use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::UNICODE_STRING;

use sediment_rs::PasswordFilter;
macro_rules! create_unicode {
    ( $data:expr ) => {{
        let mut data = String::from($data).encode_utf16().collect::<Vec<u16>>();

        UNICODE_STRING {
            Length: (data.len() * 2) as u16,
            MaximumLength: (data.capacity() * 2) as u16,
            Buffer: data.as_mut_ptr(),
        }
    }};
}

pub fn filter_good_bench(c: &mut Criterion) {
    c.bench_function("pass_good_filter", |bencher| {
        let mut password = create_unicode!(black_box("RustySediment"));
        bencher.iter(|| unsafe { PasswordFilter(null_mut(), null_mut(), &mut password, 0) })
    });
}

pub fn filter_bad_bench(c: &mut Criterion) {
    c.bench_function("pass_bad_filter", |bencher| {
        let mut password = create_unicode!(black_box("car1234"));
        bencher.iter(|| unsafe { PasswordFilter(null_mut(), null_mut(), &mut password, 0) })
    });
}

criterion_group!(benches, filter_good_bench, filter_bad_bench);
criterion_main!(benches);
