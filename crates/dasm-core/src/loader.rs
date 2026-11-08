//! The loader extension point and the registry of loaders/architectures.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::arch::Arch;
use crate::error::{Error, LoadError};
use crate::image::LoadedImage;
use crate::memory::SharedBytes;

/// Resource limits a loader must enforce on untrusted input. Exceeding a
/// limit is a [`LoadError::LimitExceeded`], never an allocation failure.
///
/// Limits are a property of the running build, **not** of a project:
/// [`LoadOptions`] does not persist them (a planted project must not be
/// able to lift them, ADR 0002). They stay `Serialize`/`Deserialize` with
/// serde defaults for configuration files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Maximum input file size in bytes.
    pub max_file_size: u64,
    /// Maximum number of sections or segments.
    pub max_sections: usize,
    /// Maximum number of symbols (all tables together).
    pub max_symbols: usize,
    /// Maximum number of relocations.
    pub max_relocations: usize,
    /// Maximum total size of mapped memory in bytes.
    pub max_mapped_size: u64,
    /// Budget for all text the loader materialises per load, in bytes:
    /// symbol and import names, relocation symbol names, demangled names,
    /// DWARF names. Guards against amplification (many small table entries
    /// pointing at one long string).
    pub max_string_bytes: u64,
    /// Work budget for debug-info parsing: DWARF DIEs plus abbreviation
    /// declarations plus `.eh_frame` CIE/FDE records visited per load.
    /// Bounds quadratic or pathological inputs; on exhaustion the loader
    /// stops reading debug info (keeping what it has) or fails with
    /// `LimitExceeded` — documented by the loader.
    pub max_debug_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_size: 4 << 30,
            max_sections: 1 << 16,
            max_symbols: 1 << 22,
            max_relocations: 1 << 23,
            max_mapped_size: 16 << 30,
            max_string_bytes: 256 << 20,
            max_debug_work: 1 << 26,
        }
    }
}

/// Options for loading.
///
/// Persisted in projects ([`crate::StoredSource::options`]) without
/// `limits`: those always come from the build (or the caller), and a
/// `limits` key in an old project file is ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoadOptions {
    /// Load base for position-independent images. `None` = the loader's
    /// default (0 for PIE, so addresses match `readelf`/`objdump`). The
    /// chosen base is persisted in the project; all journal addresses are
    /// relative to it.
    pub base: Option<Address>,
    /// Resource limits (never persisted; see [`Limits`]).
    #[serde(skip)]
    pub limits: Limits,
}

/// Parses a file format into a [`LoadedImage`].
///
/// Must never panic on any input (fuzzed by Security). Implementations are
/// stateless and `Send + Sync`.
pub trait Loader: Send + Sync {
    /// Short name (`"elf"`).
    fn name(&self) -> &'static str;

    /// Cheap check on the first bytes: does this loader handle the file?
    fn probe(&self, bytes: &[u8]) -> bool;

    /// Loads the file.
    fn load(&self, file: SharedBytes, options: &LoadOptions) -> Result<LoadedImage, LoadError>;
}

/// Known loaders and architectures. Built by the binaries (`dasm-cli`,
/// `dasm-qt`) from the concrete crates; later also filled by plugins.
#[derive(Clone, Default)]
pub struct Registry {
    loaders: Vec<Arc<dyn Loader>>,
    archs: Vec<Arc<dyn Arch>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field(
                "loaders",
                &self.loaders.iter().map(|l| l.name()).collect::<Vec<_>>(),
            )
            .field(
                "archs",
                &self.archs.iter().map(|a| a.id()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Registry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Registry::default()
    }

    /// Adds a loader (builder style).
    #[must_use]
    pub fn with_loader(mut self, loader: Arc<dyn Loader>) -> Self {
        self.loaders.push(loader);
        self
    }

    /// Adds an architecture (builder style).
    #[must_use]
    pub fn with_arch(mut self, arch: Arc<dyn Arch>) -> Self {
        self.archs.push(arch);
        self
    }

    /// Loads `file` with the first loader whose `probe` accepts it, and
    /// picks the matching architecture.
    pub fn load(
        &self,
        file: SharedBytes,
        options: &LoadOptions,
    ) -> Result<(LoadedImage, Arc<dyn Arch>), Error> {
        if file.len() as u64 > options.limits.max_file_size {
            return Err(LoadError::LimitExceeded(format!(
                "file is {} bytes, limit is {}",
                file.len(),
                options.limits.max_file_size
            ))
            .into());
        }
        let loader = self
            .loaders
            .iter()
            .find(|l| l.probe(file.as_slice()))
            .ok_or(LoadError::UnknownFormat)?;
        let image = loader.load(file, options)?;
        let arch = self
            .archs
            .iter()
            .find(|a| a.id() == image.info.arch)
            .cloned()
            .ok_or_else(|| {
                Error::Unsupported(format!("no decoder for architecture {:?}", image.info.arch))
            })?;
        Ok((image, arch))
    }
}

/// SHA-256 of a byte slice (used for `BinaryInfo::sha256` and the project
/// store's source check).
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptAll;
    impl Loader for AcceptAll {
        fn name(&self) -> &'static str {
            "all"
        }
        fn probe(&self, _bytes: &[u8]) -> bool {
            true
        }
        fn load(&self, _file: SharedBytes, _o: &LoadOptions) -> Result<LoadedImage, LoadError> {
            Err(LoadError::Unsupported("test".into()))
        }
    }

    #[test]
    fn registry_enforces_max_file_size_before_parsing() {
        let reg = Registry::new().with_loader(Arc::new(AcceptAll));
        let mut options = LoadOptions::default();
        options.limits.max_file_size = 4;
        let err = reg
            .load(SharedBytes::from(vec![0u8; 5]), &options)
            .err()
            .unwrap();
        assert!(
            matches!(err, Error::Load(LoadError::LimitExceeded(_))),
            "{err}"
        );
        let err = reg
            .load(SharedBytes::from(vec![0u8; 4]), &options)
            .err()
            .unwrap();
        assert!(
            matches!(err, Error::Load(LoadError::Unsupported(_))),
            "{err}"
        );
    }

    #[test]
    fn options_from_older_projects_get_defaults() {
        let o: LoadOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(o, LoadOptions::default());
        // A planted project cannot lift (or change) the loader limits.
        let o: LoadOptions =
            serde_json::from_str(r#"{"base":"0x1000","limits":{"max_symbols":999999999999}}"#)
                .unwrap();
        assert_eq!(o.base, Some(Address(0x1000)));
        assert_eq!(o.limits, Limits::default());
        // Config files written before a limit existed get its default.
        let l: Limits = serde_json::from_str(r#"{"max_symbols":5}"#).unwrap();
        assert_eq!(l.max_symbols, 5);
        assert_eq!(l.max_string_bytes, Limits::default().max_string_bytes);
        assert_eq!(l.max_debug_work, Limits::default().max_debug_work);
        let json = serde_json::to_string(&o).unwrap();
        assert!(!json.contains("limits"), "{json}");
    }
}
