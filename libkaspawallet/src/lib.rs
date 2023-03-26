pub mod bip39;
pub mod sign;

use bip32::Prefix;
use consensus_core::tx::{Transaction, TransactionInput, UtxoEntry, VerifiableTransaction};

pub struct PartiallySignedTx {
    pub(crate) tx: Transaction,
    pub(crate) inputs_meta_data: Vec<InputMetaData>,
}

impl PartiallySignedTx {
    pub fn new(tx: Transaction, inputs_meta_data: Vec<InputMetaData>) -> Self {
        Self { tx, inputs_meta_data }
    }
}

pub struct InputMetaData {
    pub min_signatures: usize,
    pub pub_key_sig_pairs: Vec<PubKeySigPair>,
    pub derivation_path: String,
    pub utxo_entry: UtxoEntry,
}

pub struct PubKeySigPair {
    pub extended_pubkey: String,
    pub signature: Option<Vec<u8>>,
}

impl VerifiableTransaction for PartiallySignedTx {
    fn tx(&self) -> &Transaction {
        &self.tx
    }

    fn populated_input(&self, index: usize) -> (&TransactionInput, &UtxoEntry) {
        (&self.tx.inputs[index], &self.inputs_meta_data[index].utxo_entry)
    }
}

pub const KPRV: Prefix = Prefix::from_parts_unchecked("kprv", 0x038f2ef4);
pub const KPUB: Prefix = Prefix::from_parts_unchecked("kpub", 0x038f332e);
