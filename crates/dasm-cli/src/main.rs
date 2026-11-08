//! The `dasm` binary: see the `dasm_cli` library for the logic.

fn main() {
    let services = dasm_cli::build_services();
    let env = dasm_cli::Env::from_process();
    let code = dasm_cli::run(
        std::env::args_os(),
        &services,
        &env,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    std::process::exit(code);
}
