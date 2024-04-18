use std::thread;

use ark_std::{rand::Rng, test_rng};
use crossbeam::channel::unbounded;

fn main() {
    let (tx, rx) = unbounded();
    let mut handles = vec![];

    // Spawn threads to send values
    for i in 1..=10 {
        let tx_clone = tx.clone();
        let handle = thread::spawn(move || {
            // Send the value and its intended index for ordering
            let rng = &mut test_rng();
            let idx = i as u64;
            let time = 10000 - idx*1000;
            thread::sleep(std::time::Duration::from_millis(time));
            tx_clone.send((i, i)).unwrap(); // Send (index, value)
        });
        handles.push(handle);
    }

    drop(tx); // Drop the original transmitter to close the channel

    // Prepare a vector of correct size filled with None values
    let mut results = vec![None; 10];

    // Process received messages and place them into the vector at the designated index
    for (index, value) in rx {
        results[index - 1] = Some(value); // Place value based on index
    }

    // Ensure all threads are complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Convert the vector of Option to a vector of integers
    let final_results: Vec<_> = results.into_iter().map(|x| x.unwrap()).collect();

    println!("Collected numbers in order: {:?}", final_results);
}
