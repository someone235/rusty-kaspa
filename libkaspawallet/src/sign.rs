use bip32::{DerivationPath, ExtendedPrivateKey, Prefix, PrivateKey};
use consensus_core::{hashing::sighash::SigHashReusedValues, sign::raw_schnorr_input_signature, tx::Transaction};
use txscript::script_builder::ScriptBuilder;

use crate::PartiallySignedTx;

pub fn sign<K: PrivateKey + Clone>(ext_prv: ExtendedPrivateKey<K>, pstx: &mut PartiallySignedTx, is_ecdsa: bool, prefix: Prefix) {
    assert!(!is_ecdsa, "ecdsa is not supported yet"); //TODO: Support ECDSA
    if is_fully_signed(pstx) {
        return;
    }

    let mut reused_values = SigHashReusedValues::new();
    for (input, input_data) in pstx.tx.inputs.iter_mut().zip(pstx.inputs_meta_data.iter_mut()) {
        input.sig_op_count = input_data.pub_key_sig_pairs.len() as u8;
    }

    let mut sigs_to_change = Vec::new();
    for (input_idx, input_data) in pstx.inputs_meta_data.iter().enumerate() {
        let derived_key = derive_from_path(ext_prv.clone(), &input_data.derivation_path);
        let derived_public_key = derived_key.public_key().to_string(prefix);
        for pair_idx in input_data
            .pub_key_sig_pairs
            .iter()
            .filter(|pair| pair.extended_pubkey == derived_public_key)
            .enumerate()
            .map(|(pair_idx, _)| pair_idx)
        {
            sigs_to_change.push((
                raw_schnorr_input_signature(pstx, derived_key.private_key().to_bytes(), input_idx, &mut reused_values),
                input_idx,
                pair_idx,
            ));
        }
    }

    if sigs_to_change.is_empty() {
        panic!("Private key doesn't match any of the transaction public keys"); // TODO: Return error
    }

    for (sig, input_idx, pair_idx) in sigs_to_change {
        pstx.inputs_meta_data[input_idx].pub_key_sig_pairs[pair_idx].signature = Some(sig.into());
    }
}

fn is_fully_signed(tx: &PartiallySignedTx) -> bool {
    tx.inputs_meta_data.iter().all(|input_data| {
        let num_sigs = input_data.pub_key_sig_pairs.iter().filter(|pair| pair.signature.is_some()).count();
        num_sigs >= input_data.min_signatures
    })
}

fn derive_from_path<K: PrivateKey>(ext_prv: ExtendedPrivateKey<K>, path: &str) -> ExtendedPrivateKey<K> {
    let path: DerivationPath = path.parse().unwrap(); //TODO: Return error
    path.into_iter().fold(ext_prv, |derived, child_num| derived.derive_child(child_num).unwrap())
}

pub fn extract_transaction(pstx: &mut PartiallySignedTx, is_ecdsa: bool) -> &Transaction {
    assert!(!is_ecdsa, "ecdsa is not supported yet"); //TODO: Support ECDSA
    assert!(is_fully_signed(pstx)); // TODO: Return error

    for (input_data, input) in pstx.inputs_meta_data.iter().zip(pstx.tx.inputs.iter_mut()) {
        let is_multisig = input_data.pub_key_sig_pairs.len() > 1;
        assert!(!is_multisig, "multisig is not supported yet"); // TODO: Support multisig
        let mut sb = ScriptBuilder::new();
        input.signature_script =
            sb.add_data(input_data.pub_key_sig_pairs[0].signature.as_ref().expect("checked with is_fully_signed")).unwrap().drain();
        // TODO: Return error
    }
    &pstx.tx
}
