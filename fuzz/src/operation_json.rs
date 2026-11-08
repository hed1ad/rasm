//! JSON → `Operation` → `UserState::apply` → inverse.
//!
//! Oracles: the JSON form round-trips; a failed apply leaves the state
//! untouched; an applied operation is exactly undone by its inverse and
//! redone by the inverse of the inverse (ADR 0002).

use dasm_core::Operation;

use crate::check;
use crate::fixtures::{base_state, fingerprint};

/// The target.
pub fn run(data: &[u8]) {
    let Ok(op) = serde_json::from_slice::<Operation>(data) else {
        return;
    };
    let _ = op.changes();
    let _ = op.primary_address();
    let valid = op.validate().is_ok();
    round_trip(&op);

    let mut state = base_state();
    let before = fingerprint(&state);
    let inverse = match state.apply(&op) {
        Ok(inv) => inv,
        Err(_) => {
            check!(
                fingerprint(&state) == before,
                "OPS-01",
                "failed apply changed state: {op:?}"
            );
            return;
        }
    };
    check!(
        valid,
        "OPS-02",
        "apply accepted an operation validate() rejects: {op:?}"
    );
    round_trip(&inverse);
    let after = fingerprint(&state);
    match state.apply(&inverse) {
        Ok(redo) => {
            check!(
                fingerprint(&state) == before,
                "OPS-03",
                "inverse does not restore state: {op:?}"
            );
            match state.apply(&redo) {
                Ok(_) => check!(
                    fingerprint(&state) == after,
                    "OPS-03",
                    "redo differs: {op:?}"
                ),
                Err(e) => check!(false, "OPS-03", "redo of {op:?} fails: {e}"),
            }
        }
        Err(e) => check!(false, "OPS-03", "inverse {inverse:?} of {op:?} fails: {e}"),
    }
}

fn round_trip(op: &Operation) {
    match serde_json::to_vec(op) {
        Ok(json) => match serde_json::from_slice::<Operation>(&json) {
            Ok(back) => check!(
                &back == op,
                "OPS-04",
                "JSON round trip changed {op:?} to {back:?}"
            ),
            Err(e) => check!(false, "OPS-04", "own JSON of {op:?} does not parse: {e}"),
        },
        Err(e) => check!(false, "OPS-04", "{op:?} does not serialize: {e}"),
    }
}
