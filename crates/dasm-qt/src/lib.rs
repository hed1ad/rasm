//! # dasm-qt
//!
//! Rust half of the Qt UI bridge (cxx-qt): the `SessionObject` QObject and
//! plain data records that expose [`dasm_core::Session`] and
//! [`dasm_core::Snapshot`] to the C++ Qt Widgets application in `ui/`
//! (ADR 0005). Built as a static library and linked by CMake via
//! `cxx_qt_import_crate`.
//!
//! The UI thread only reads snapshots; change notifications are coalesced
//! so that a burst of publications costs the UI one or two events.

mod bridge;
mod data;
mod open;
