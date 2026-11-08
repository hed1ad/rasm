//! Generates the cxx-qt glue for the bridge module.

use cxx_qt_build::CxxQtBuilder;

fn main() {
    CxxQtBuilder::new().file("src/bridge.rs").build();
}
