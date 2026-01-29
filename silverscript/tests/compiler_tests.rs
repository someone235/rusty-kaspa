use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use silverscript::compiler::{CompileOptions, compile_contract, function_branch_index};

fn run_script_with_selector(script: Vec<u8>, selector: i64) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();
    run_script_with_sigscript(script, sigscript)
}

fn run_script_with_tx(
    script: Vec<u8>,
    selector: i64,
    lock_time: u64,
    sequence: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let sigscript = ScriptBuilder::new().add_i64(selector).unwrap().drain();

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0u8; 32]), index: 0 },
        signature_script: sigscript,
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

fn selector_for(source: &str, function_name: &str) -> i64 {
    function_branch_index(source, function_name).expect("selector resolved")
}

fn wrap_with_dispatch(body: Vec<u8>, selector: i64) -> Vec<u8> {
    let mut builder = ScriptBuilder::new();
    builder.add_op(OpDup).unwrap();
    builder.add_i64(selector).unwrap();
    builder.add_op(OpNumEqual).unwrap();
    builder.add_op(OpIf).unwrap();
    builder.add_op(OpDrop).unwrap();
    builder.add_ops(&body).unwrap();
    builder.add_op(OpElse).unwrap();
    builder.add_op(OpDrop).unwrap();
    builder.add_op(OpFalse).unwrap();
    builder.add_op(OpVerify).unwrap();
    builder.add_op(OpEndIf).unwrap();
    builder.drain()
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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");

    let body = ScriptBuilder::new()
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

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

#[test]
fn compiles_contract_constants_and_verifies() {
    let source = r#"
        contract Test() {
            int constant MAX_SUPPLY = 1_000_000;

            function main() {
                require(MAX_SUPPLY == 1_000_000);
            }
        }
    "#;

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");

    let body = ScriptBuilder::new()
        .add_i64(1_000_000)
        .unwrap()
        .add_i64(1_000_000)
        .unwrap()
        .add_op(OpNumEqual)
        .unwrap()
        .add_op(OpVerify)
        .unwrap()
        .add_op(OpTrue)
        .unwrap()
        .drain();

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
}

fn assert_compiled_body(source: &str, body: Vec<u8>) {
    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");
    let expected = wrap_with_dispatch(body, selector);
    assert_eq!(compiled.script, expected);
}

#[test]
fn compiles_opcode_builtins() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpSha256(bytes("msg")) == bytes("hash"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"msg")
                .unwrap()
                .add_op(OpSHA256)
                .unwrap()
                .add_data(b"hash")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxSubnetId() == bytes("subnet"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_op(OpTxSubnetId)
                .unwrap()
                .add_data(b"subnet")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxGas() == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_op(OpTxGas)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxPayloadLen() >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_op(OpTxPayloadLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxPayloadSubstr(1, 3) == bytes("ok"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(1)
                .unwrap()
                .add_i64(3)
                .unwrap()
                .add_op(OpTxPayloadSubstr)
                .unwrap()
                .add_data(b"ok")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpOutpointTxId(0) == bytes("txid"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpOutpointTxId)
                .unwrap()
                .add_data(b"txid")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpOutpointIndex(0) == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpOutpointIndex)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxInputScriptSigLen(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputScriptSigLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxInputScriptSigSubstr(0, 0, 1) == bytes("sig"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxInputScriptSigSubstr)
                .unwrap()
                .add_data(b"sig")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxInputSeq(0) == bytes("seq"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputSeq)
                .unwrap()
                .add_data(b"seq")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxInputIsCoinbase(0) == 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputIsCoinbase)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxInputSpkLen(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxInputSpkLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxInputSpkSubstr(0, 0, 1) == bytes("spk"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxInputSpkSubstr)
                .unwrap()
                .add_data(b"spk")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxOutputSpkLen(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpTxOutputSpkLen)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpTxOutputSpkSubstr(0, 0, 1) == bytes("out"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_i64(1)
                .unwrap()
                .add_op(OpTxOutputSpkSubstr)
                .unwrap()
                .add_data(b"out")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpAuthOutputCount(0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpAuthOutputCount)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpAuthOutputIdx(0, 0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpAuthOutputIdx)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpInputCovenantId(0) == bytes("cov"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(0)
                .unwrap()
                .add_op(OpInputCovenantId)
                .unwrap()
                .add_data(b"cov")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpCovInputCount(bytes("c1")) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
                .unwrap()
                .add_op(OpCovInputCount)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpCovInputIdx(bytes("c1"), 0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpCovInputIdx)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpCovOutCount(bytes("c1")) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
                .unwrap()
                .add_op(OpCovOutCount)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpCovOutputIdx(bytes("c1"), 0) >= 0);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"c1")
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpCovOutputIdx)
                .unwrap()
                .add_i64(0)
                .unwrap()
                .add_op(OpGreaterThanOrEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpNum2Bin(5, 2) == bytes("bin"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_i64(5)
                .unwrap()
                .add_i64(2)
                .unwrap()
                .add_op(OpNum2Bin)
                .unwrap()
                .add_data(b"bin")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpBin2Num(bytes("a")) == 5);
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"a")
                .unwrap()
                .add_op(OpBin2Num)
                .unwrap()
                .add_i64(5)
                .unwrap()
                .add_op(OpNumEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
        (
            r#"
                contract Test() {
                    function main() {
                        require(OpChainblockSeqCommit(bytes("block")) == bytes("commit"));
                    }
                }
            "#,
            ScriptBuilder::new()
                .add_data(b"block")
                .unwrap()
                .add_op(OpChainblockSeqCommit)
                .unwrap()
                .add_data(b"commit")
                .unwrap()
                .add_op(OpEqual)
                .unwrap()
                .add_op(OpVerify)
                .unwrap()
                .add_op(OpTrue)
                .unwrap()
                .drain(),
        ),
    ];

    for (source, body) in cases {
        assert_compiled_body(source, body);
    }
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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");

    let body = ScriptBuilder::new()
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

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");

    let body = ScriptBuilder::new().add_i64(10).unwrap().add_op(OpCheckSequenceVerify).unwrap().add_op(OpTrue).unwrap().drain();
    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_tx(compiled.script, selector, 0, 20).is_ok());
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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");

    let body = ScriptBuilder::new()
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

    let expected = wrap_with_dispatch(body, selector);

    assert_eq!(compiled.script, expected);
    assert!(run_script_with_selector(compiled.script, selector).is_ok());
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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");
    let sigscript = ScriptBuilder::new().add_i64(3).unwrap().add_i64(4).unwrap().add_i64(selector).unwrap().drain();

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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");
    let sigscript = ScriptBuilder::new().add_i64(3).unwrap().add_i64(selector).unwrap().drain();

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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");
    let sigscript = ScriptBuilder::new().add_i64(2).unwrap().add_i64(4).unwrap().add_i64(selector).unwrap().drain();

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

    let compiled = compile_contract(source, CompileOptions::default()).expect("compile succeeds");
    let selector = selector_for(source, "main");
    let sigscript = ScriptBuilder::new().add_i64(4).unwrap().add_i64(selector).unwrap().drain();

    let result = run_script_with_sigscript(compiled.script, sigscript);
    assert!(result.is_err());
}
