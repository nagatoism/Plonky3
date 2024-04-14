use bitcoin::blockdata::transaction;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::{hashes::Hash, TapLeafHash, Transaction as TX};
use bitcoin_script::define_pushable;
use bitcoin_scriptexec::{Exec, ExecCtx, ExecutionResult, Options, TxTemplate};
mod u31;
pub use u31::*;

mod u31_ext;
pub use u31_ext::*;

mod fri;
pub use fri::*;

mod u32;
pub use u32::*;

pub mod pseudo;
define_pushable!();

#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use crate::execute_script;
    pub use bitcoin_script::{define_pushable, script};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

pub fn unroll<F, T>(count: u32, mut closure: F) -> Vec<T>
where
    F: FnMut(u32) -> T,
    T: pushable::Pushable,
{
    let mut result = vec![];

    for i in 0..count {
        result.push(closure(i))
    }
    result
}

pub fn execute_script(script: bitcoin::ScriptBuf) -> ExecutionResult {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script,
        vec![],
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    res.clone()
}

pub fn execute_script_with_inputs(
    script: bitcoin::ScriptBuf,
    witness: Vec<Vec<u8>>,
) -> ExecutionResult {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script,
        witness,
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    res.clone()
}
