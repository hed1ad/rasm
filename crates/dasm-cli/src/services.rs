//! The single place where the concrete loaders, architectures and the
//! analysis driver are chosen.

use std::sync::Arc;

use dasm_core::{AnalysisDriver, NoAnalysis, Registry};

/// Everything the CLI needs from the backends.
pub struct Services {
    /// Known loaders and architectures.
    pub registry: Registry,
    /// Creates a fresh analysis driver for each session.
    pub driver: Box<dyn Fn() -> Arc<dyn AnalysisDriver> + Send + Sync>,
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

/// Builds the production services: the ELF loader, x86-64 and the analysis
/// scheduler.
#[must_use]
pub fn build_services() -> Services {
    Services {
        registry: Registry::new()
            .with_loader(Arc::new(dasm_elf::ElfLoader))
            .with_arch(Arc::new(dasm_x86::X86_64)),
        driver: Box::new(
            || match dasm_analysis::Scheduler::new(dasm_analysis::Config::default()) {
                Ok(s) => Arc::new(s) as Arc<dyn AnalysisDriver>,
                Err(e) => {
                    eprintln!("dasm: warning: analysis is unavailable: {e}");
                    Arc::new(NoAnalysis)
                }
            },
        ),
    }
}
