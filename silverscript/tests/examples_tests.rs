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
use silverscript::parser::parse_source_file;

fn assert_parses(source: &str) {
    let result = parse_source_file(source);
    if let Err(err) = result {
        panic!("failed to parse example: {err}");
    }
}

fn build_null_data_script(tag: i64, message: &str) -> Vec<u8> {
    ScriptBuilder::new().add_op(OpReturn).unwrap().add_i64(tag).unwrap().add_data(message.as_bytes()).unwrap().drain()
}

fn run_contract_with_tx(
    script: Vec<u8>,
    output0_script: Vec<u8>,
    input_value: u64,
    output1_value: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 0,
    };
    let output0 = TransactionOutput { value: 0, script_public_key: ScriptPublicKey::new(0, output0_script.into()), covenant: None };
    let output1 =
        TransactionOutput { value: output1_value, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output0.clone(), output1.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(input_value, ScriptPublicKey::new(0, script.clone().into()), 0, tx.is_coinbase(), None);
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
fn compiles_announcement_example_and_verifies() {
    let source = r#"
        pragma cashscript ^0.12.0;

        contract Announcement() {
            function announce() {
                bytes announcement = new LockingBytecodeNullData([
                    27906,
                    bytes('A contract may not injure a human being or, through inaction, allow a human being to come to harm.')
                ]);

                require(tx.outputs[0].value == 0);
                require(tx.outputs[0].lockingBytecode == announcement);

                int minerFee = 1000;
                int changeAmount = tx.inputs[this.activeInputIndex].value - minerFee;
                if (changeAmount >= minerFee) {
                    require(tx.outputs[1].lockingBytecode == tx.inputs[this.activeInputIndex].lockingBytecode);
                    require(tx.outputs[1].value == changeAmount);
                }
            }
        }
    "#;

    let compiled = compile_contract(source, Some("announce"), CompileOptions::default()).expect("compile succeeds");
    let message = "A contract may not injure a human being or, through inaction, allow a human being to come to harm.";
    let announcement_script = build_null_data_script(27906, message);
    let input_value = 3000u64;
    let output1_value = input_value - 1000;

    let result = run_contract_with_tx(compiled.script, announcement_script, input_value, output1_value);
    assert!(result.is_ok(), "announcement example failed: {}", result.unwrap_err());
}

#[test]
fn parses_hodl_vault_example() {
    let source = r#"
        pragma cashscript ^0.12.0;

        contract HodlVault(
            pubkey ownerPk,
            pubkey oraclePk,
            int minBlock,
            int priceTarget
        ) {
            function spend(sig ownerSig, datasig oracleSig, bytes oracleMessage) {
                bytes4 blockHeightBin, bytes4 priceBin = oracleMessage.split(4);
                int blockHeight = int(blockHeightBin);
                int price = int(priceBin);

                require(blockHeight >= minBlock);
                require(tx.time >= blockHeight);
                require(price >= priceTarget);

                require(checkDataSig(oracleSig, oracleMessage, oraclePk));
                require(checkSig(ownerSig, ownerPk));
            }
        }
    "#;

    assert_parses(source);
}

#[test]
fn parses_mecenas_example() {
    let source = r#"
        pragma cashscript ^0.12.0;

        contract Mecenas(bytes20 recipient, bytes20 funder, int pledge) {
            function receive() {
                require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2PKH(recipient));

                int minerFee = 1000;
                int currentValue = tx.inputs[this.activeInputIndex].value;
                int changeValue = currentValue - pledge - minerFee;

                if (changeValue <= pledge + minerFee) {
                    require(tx.outputs[0].value == currentValue - minerFee);
                } else {
                    require(tx.outputs[0].value == pledge);
                    require(tx.outputs[1].lockingBytecode == tx.inputs[this.activeInputIndex].lockingBytecode);
                    require(tx.outputs[1].value == changeValue);
                }
            }

            function reclaim(pubkey pk, sig s) {
                require(blake2b(pk) == funder);
                require(checkSig(s, pk));
            }
        }
    "#;

    assert_parses(source);
}

#[test]
fn parses_mecenas_locktime_example() {
    let source = r#"
        pragma cashscript ^0.12.0;

        contract Mecenas(
            bytes20 recipient,
            bytes20 funder,
            int pledgePerBlock,
            bytes8 initialBlock,
        ) {
            function receive() {
                bytes25 recipientLockingBytecode = new LockingBytecodeP2PKH(recipient);
                require(tx.outputs[0].lockingBytecode == recipientLockingBytecode);

                int initial = int(initialBlock);
                require(tx.time >= initial);

                int passedBlocks = tx.locktime - initial;
                int pledge = passedBlocks * pledgePerBlock;

                int minerFee = 1000;
                int currentValue = tx.inputs[this.activeInputIndex].value;
                int changeValue = currentValue - pledge - minerFee;

                if (changeValue <= pledgePerBlock + minerFee) {
                    require(tx.outputs[0].value == currentValue - minerFee);
                } else {
                    require(tx.outputs[0].value == pledge);
                    require(tx.outputs[1].value == changeValue);

                    bytes bcValue = 8 + bytes8(tx.locktime) + this.activeBytecode.split(9)[1];
                    bytes23 lockValue = new LockingBytecodeP2SH20(blake2b(bcValue));
                    require(tx.outputs[1].lockingBytecode == lockValue);
                }
            }

            function reclaim(pubkey pk, sig s) {
                require(blake2b(pk) == funder);
                require(checkSig(s, pk));
            }
        }
    "#;

    assert_parses(source);
}

#[test]
fn parses_p2pkh_example() {
    let source = r#"
        pragma cashscript ^0.12.0;

        contract P2PKH(bytes20 pkh) {
            function spend(pubkey pk, sig s) {
                require(blake2b(pk) == pkh);
                require(checkSig(s, pk));
            }
        }
    "#;

    assert_parses(source);
}

#[test]
fn parses_transfer_with_timeout_example() {
    let source = r#"
        pragma cashscript ^0.12.0;

        contract TransferWithTimeout(
            pubkey sender,
            pubkey recipient,
            int timeout
        ) {
            function transfer(sig recipientSig) {
                require(checkSig(recipientSig, recipient));
            }

            function timeout(sig senderSig) {
                require(checkSig(senderSig, sender));
                require(tx.time >= timeout);
            }
        }
    "#;

    assert_parses(source);
}
