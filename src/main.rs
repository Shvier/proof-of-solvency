use std::{
    env, io, path::Path
};

use proof_of_solvency::
    main_pol::run_pol
;

fn main() {
    println!("Operation:");
    println!("1. Run Proof-of-Liability");
    println!("2. Run whole Proof-of-Assets");
    println!("3. Run precomputation for Proof-of-Assets");
    println!("4. Run Proof-of-Assets");
    println!("5. Exit");

    println!("Enter your choice:");

    let mut choice = String::new();

    io::stdin()
        .read_line(&mut choice)
        .expect("Failed to read line");

    let choice: u32 = match choice.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Please enter a valid number!");
            return;
        }
    };

    let args: Vec<String> = env::args().collect();
    
    match choice {
        1 => {
            println!("You chose Option 1");
            let bal_path = &args[1];
            let output_dir = &args[2];
            assert!(Path::new(bal_path).exists());
            run_pol(bal_path.to_string(), output_dir.to_string());
        }
        2 => {
            println!("You chose Option 2");
        }
        3 => {
            println!("You chose Option 3");
        }
        4 => {
            println!("You chose Option 4");
        }
        5 => {
            println!("Exiting...");
            return;
        }
        _ => println!("Invalid choice!"),
    }
}

// fn to_disk<T: Sized>(path: &str, data: &T) {
//     unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
//         ::core::slice::from_raw_parts(
//             (p as *const T) as *const u8,
//             ::core::mem::size_of::<T>(),
//         )
//     }
//     let mut fs = File::create(path).expect("failed to create pol");
//     fs.write_all(unsafe { &any_as_u8_slice(data) }).expect("failed to write pol");
// }
