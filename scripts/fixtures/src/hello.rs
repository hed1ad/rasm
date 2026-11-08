// Rust fixture: generics, trait objects, panics (unwinding tables), strings.
use std::collections::HashMap;

trait Animal {
    fn name(&self) -> String;
}
struct Dog;
struct Cat(u32);
impl Animal for Dog {
    fn name(&self) -> String {
        "dog".to_string()
    }
}
impl Animal for Cat {
    fn name(&self) -> String {
        format!("cat{}", self.0)
    }
}

fn collatz(mut n: u64) -> u32 {
    let mut steps = 0;
    while n != 1 {
        n = if n % 2 == 0 { n / 2 } else { 3 * n + 1 };
        steps += 1;
    }
    steps
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let zoo: Vec<Box<dyn Animal>> = vec![Box::new(Dog), Box::new(Cat(args.len() as u32))];
    let mut counts: HashMap<String, u32> = HashMap::new();
    for a in &zoo {
        *counts.entry(a.name()).or_default() += collatz(27 + args.len() as u64);
    }
    let mut keys: Vec<_> = counts.into_iter().collect();
    keys.sort();
    println!("Hello from Rust: {keys:?}");
    if args.len() > 9 {
        panic!("too many args");
    }
}
