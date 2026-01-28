use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use silverscript::compiler::{CompileOptions, compile_contract};

fn run_script(script: Vec<u8>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::<kaspa_consensus_core::tx::PopulatedTransaction<'static>, SigHashReusedValuesUnsync>::from_script(
        &script,
        &reused_values,
        &sig_cache,
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn run_script_with_tx(script: Vec<u8>, lock_time: u64, sequence: u64) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0u8; 32]), index: 0 },
        signature_script: vec![],
        sequence,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], lock_time, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn run_script_with_sigscript(script: Vec<u8>, sigscript: Vec<u8>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

#[test]
fn compiles_basic_arithmetic_and_verifies() {
    let source = r#"
        contract Test() {
            function main() {
                require(1 + 2 == 3);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_i64(1)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
    assert!(run_script(compiled.script).is_ok());
}

#[test]
fn compiles_if_else_and_verifies() {
    let source = r#"
        contract Test() {
            function main() {
                if (1 < 2) {
                    require(true);
                } else {
                    require(false);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_i64(1)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_op(OpLessThan)
        .unwrap()
        .add_op(OpIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpElse)
        .unwrap()
        .add_op(OpFalse)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpEndIf)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
    assert!(run_script(compiled.script).is_ok());
}

#[test]
fn compiles_time_op_csv_and_verifies() {
    let source = r#"
        contract Test() {
            function main() {
                require(this.age >= 10);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new().add_i64(10).unwrap().add_op(OpCheckSequenceVerify).unwrap().add_op(OpTrue).unwrap().drain();

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_tx(compiled.script, 0, 20).is_ok());
}

#[test]
fn compiles_reused_variables_and_verifies() {
    let source = r#"
        contract Test() {
            function main() {
                int a = 2 + 3;
                int b = a * a + a;
                require(b == 30);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");

    let expected = ScriptBuilder::new()
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpMul)
        .unwrap()
        .add_i64(2)
        .unwrap()
        .add_i64(3)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_op(OpAdd)
        .unwrap()
        .add_i64(30)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    assert_eq!(compiled.script, expected);
    assert!(run_script(compiled.script).is_ok());
}

#[test]
fn compiles_sigscript_inputs_and_verifies() {
    let source = r#"
        contract Test() {
            function main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().add_i64(3).unwrap().add_i64(4).unwrap().drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "sigscript test failed: {}", result.unwrap_err());
}

#[test]
fn compiles_sigscript_reused_inputs_and_verifies() {
    let source = r#"
        contract Test() {
            function main(int a) {
                require(a * a + a == 12);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().add_i64(3).unwrap().drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_ok(), "sigscript reuse test failed: {}", result.unwrap_err());
}

#[test]
fn compiles_sigscript_inputs_and_fails_on_wrong_sum() {
    let source = r#"
        contract Test() {
            function main(int a, int b) {
                require(a + b == 7);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().add_i64(2).unwrap().add_i64(4).unwrap().drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}

#[test]
fn compiles_sigscript_reused_inputs_and_fails_on_wrong_value() {
    let source = r#"
        contract Test() {
            function main(int a) {
                require(a * a + a == 12);
            }
        }
    "#;

    let compiled = compile_contract(source, Some("main"), CompileOptions::default()).expect("compile succeeds");
    let sigscript = ScriptBuilder::new().add_i64(4).unwrap().drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}
