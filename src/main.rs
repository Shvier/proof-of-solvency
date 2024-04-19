use std::{fs::File, io::{Read, Write}};

fn main() {
    let mut file = File::open("pol_data").expect("");
    let mut buffer = Vec::<u8>::new();
    let res = file.read_to_end(&mut buffer);
    println!("size: {}", res.unwrap());
}

fn to_disk(path: &str, data: &Vec<u8>) {
    unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::core::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::core::mem::size_of::<T>(),
        )
    }
    let mut fs = File::create(path).expect("failed to create pol");
    fs.write_all(unsafe { &any_as_u8_slice(data) }).expect("failed to write pol");
}
