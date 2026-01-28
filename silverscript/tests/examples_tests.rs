use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use rand::thread_rng;
use secp256k1::Keypair;
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
    output1_script: Vec<u8>,
    input_value: u64,
    output0_value: u64,
    output1_value: u64,
    sigscript: Vec<u8>,
    lock_time: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([9u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        sig_op_count: 0,
    };
    let output0 =
        TransactionOutput { value: output0_value, script_public_key: ScriptPublicKey::new(0, output0_script.into()), covenant: None };
    let output1 =
        TransactionOutput { value: output1_value, script_public_key: ScriptPublicKey::new(0, output1_script.into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output0.clone(), output1.clone()], lock_time, Default::default(), 0, vec![]);
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

    let result = run_contract_with_tx(
        compiled.script.clone(),
        announcement_script,
        compiled.script,
        input_value,
        0,
        output1_value,
        vec![],
        0,
    );
    assert!(result.is_ok(), "announcement example failed: {}", result.unwrap_err());
}

fn build_p2pkh_script(hash: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_op(OpBlake2b).unwrap().add_data(hash).unwrap().add_op(OpEqual).unwrap().drain()
}

fn build_p2sh20_script(hash: &[u8]) -> Vec<u8> {
    ScriptBuilder::new().add_op(OpBlake2b).unwrap().add_data(hash).unwrap().add_op(OpEqual).unwrap().drain()
}

#[test]
fn compiles_hodl_vault_example_and_verifies() {
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

    let compiled = compile_contract(source, Some("spend"), CompileOptions::default()).expect("compile succeeds");

    let owner = Keypair::new(secp256k1::SECP256K1, &mut thread_rng());
    let oracle = Keypair::new(secp256k1::SECP256K1, &mut thread_rng());
    let owner_pk = owner.x_only_public_key().0.serialize();
    let oracle_pk = oracle.x_only_public_key().0.serialize();

    let min_block = 900i64;
    let price_target = 10i64;
    let block_height = 1000u32;
    let price = 20u32;
    let oracle_message = [block_height.to_le_bytes(), price.to_le_bytes()].concat();

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([7u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output =
        TransactionOutput { value: 5000, script_public_key: ScriptPublicKey::new(0, compiled.script.clone().into()), covenant: None };

    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], block_height as u64, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, ScriptPublicKey::new(0, compiled.script.clone().into()), 0, tx.is_coinbase(), None);
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo_entry.clone()]);

    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = owner.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    let mut builder = ScriptBuilder::new();
    builder.add_data(owner_pk.as_slice()).unwrap();
    builder.add_data(oracle_pk.as_slice()).unwrap();
    builder.add_i64(min_block).unwrap();
    builder.add_i64(price_target).unwrap();
    builder.add_data(&signature).unwrap();
    builder.add_data(b"oracle").unwrap();
    builder.add_data(&oracle_message).unwrap();
    tx.tx.inputs[0].signature_script = builder.drain();

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true },
    );

    let result = vm.execute();
    assert!(result.is_ok(), "hodl_vault example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_mecenas_example_and_verifies() {
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

    let compiled = compile_contract(source, Some("receive"), CompileOptions::default()).expect("compile succeeds");
    let recipient = [1u8; 20];
    let funder = [2u8; 20];
    let pledge = 2000i64;

    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(&recipient).unwrap();
    sigscript.add_data(&funder).unwrap();
    sigscript.add_i64(pledge).unwrap();

    let input_value = 10000u64;
    let output0_value = pledge as u64;
    let output1_value = input_value - pledge as u64 - 1000;
    let output0_script = build_p2pkh_script(&recipient);

    let result = run_contract_with_tx(
        compiled.script.clone(),
        output0_script,
        compiled.script,
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        0,
    );
    assert!(result.is_ok(), "mecenas example failed: {}", result.unwrap_err());
}

#[test]
fn compiles_mecenas_locktime_example_and_verifies() {
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

    let compiled = compile_contract(source, Some("receive"), CompileOptions::default()).expect("compile succeeds");
    let recipient = [3u8; 20];
    let funder = [4u8; 20];
    let pledge_per_block = 100i64;
    let initial_block = 900u64;
    let lock_time = 1000u64;
    let passed_blocks = lock_time - initial_block;
    let pledge = passed_blocks as i64 * pledge_per_block;

    let mut sigscript = ScriptBuilder::new();
    sigscript.add_data(&recipient).unwrap();
    sigscript.add_data(&funder).unwrap();
    sigscript.add_i64(pledge_per_block).unwrap();
    sigscript.add_data(&initial_block.to_le_bytes()).unwrap();

    let input_value = 20000u64;
    let output0_value = pledge as u64;
    let output1_value = input_value - pledge as u64 - 1000;

    let output0_script = build_p2pkh_script(&recipient);
    let mut active_bytecode = Vec::with_capacity(2 + compiled.script.len());
    active_bytecode.extend_from_slice(&0u16.to_be_bytes());
    active_bytecode.extend_from_slice(&compiled.script);
    let mut bc_value = Vec::new();
    bc_value.push(8u8);
    bc_value.extend_from_slice(&lock_time.to_le_bytes());
    bc_value.extend_from_slice(&active_bytecode[9..]);
    let mut hash = blake2b_simd::Params::new().hash_length(32).to_state().update(&bc_value).finalize().as_bytes().to_vec();
    hash.truncate(20);
    let output1_script = build_p2sh20_script(&hash);

    let result = run_contract_with_tx(
        compiled.script,
        output0_script,
        output1_script,
        input_value,
        output0_value,
        output1_value,
        sigscript.drain(),
        lock_time,
    );
    assert!(result.is_ok(), "mecenas_locktime example failed: {}", result.unwrap_err());
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
