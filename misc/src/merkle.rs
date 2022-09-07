use consensus_core::{hashing, tx::Transaction};
use hashes::{Hash, Hasher, MerkleBranchHash};

fn calc_merkle_root(hashes: impl ExactSizeIterator<Item = Hash>) -> Hash {
    let next_pot = hashes.len().next_power_of_two();
    let vec_len = 2 * next_pot - 1;
    let mut merkles = vec![None; vec_len];
    for (i, hash) in hashes.enumerate() {
        merkles[i] = Some(hash);
    }
    let mut offset = next_pot;
    for i in (0..vec_len - 1).step_by(2) {
        if merkles[i].is_none() {
            merkles[offset] = None;
        } else {
            merkles[offset] = Some(merkle_hash(merkles[i].unwrap(), merkles[i + 1].unwrap_or_default()));
        }
        offset += 1
    }
    merkles.last().unwrap().unwrap()
}

pub fn calc_hash_merkle_root<'a>(txs: impl ExactSizeIterator<Item = &'a Transaction>) -> Hash {
    calc_merkle_root(txs.map(hashing::tx::hash))
}

fn merkle_hash(left: Hash, right: Hash) -> Hash {
    let mut hasher = MerkleBranchHash::new();
    hasher.update(left.as_bytes()).update(right);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use consensus_core::{
        subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE},
        tx::{ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput},
    };
    use hashes::Hash;

    use crate::merkle::calc_hash_merkle_root;

    #[test]
    fn merkle_root_test() {
        let txs = vec![
            Transaction::new(
                0,
                vec![Arc::new(TransactionInput {
                    previous_outpoint: TransactionOutpoint {
                        transaction_id: TransactionId::from_slice(&[
                            0x9b, 0x22, 0x59, 0x44, 0x66, 0xf0, 0xbe, 0x50, 0x7c, 0x1c, 0x8a, 0xf6, 0x06, 0x27, 0xe6,
                            0x33, 0x38, 0x7e, 0xd1, 0xd5, 0x8c, 0x42, 0x59, 0x1a, 0x31, 0xac, 0x9a, 0xa6, 0x2e, 0xd5,
                            0x2b, 0x0f,
                        ]),
                        index: 0xffffffff,
                    },
                    signature_script: vec![],
                    sequence: u64::MAX,
                    sig_op_count: 0,
                    utxo_entry: None,
                })],
                vec![Arc::new(TransactionOutput {
                    value: 0x12a05f200,
                    script_public_key: Arc::new(ScriptPublicKey {
                        script: vec![
                            0xa9, 0x14, 0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71,
                            0xc7, 0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b, 0x87,
                        ],
                        version: 0,
                    }),
                })],
                0,
                SUBNETWORK_ID_COINBASE,
                0,
                vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                0,
                0,
            ),
            Transaction::new(
                0,
                vec![
                    Arc::new(TransactionInput {
                        previous_outpoint: TransactionOutpoint {
                            transaction_id: TransactionId::from_slice(&[
                                0x16, 0x5e, 0x38, 0xe8, 0xb3, 0x91, 0x45, 0x95, 0xd9, 0xc6, 0x41, 0xf3, 0xb8, 0xee,
                                0xc2, 0xf3, 0x46, 0x11, 0x89, 0x6b, 0x82, 0x1a, 0x68, 0x3b, 0x7a, 0x4e, 0xde, 0xfe,
                                0x2c, 0x00, 0x00, 0x00,
                            ]),
                            index: 0xffffffff,
                        },
                        signature_script: vec![],
                        sequence: u64::MAX,
                        sig_op_count: 0,
                        utxo_entry: None,
                    }),
                    Arc::new(TransactionInput {
                        previous_outpoint: TransactionOutpoint {
                            transaction_id: TransactionId::from_slice(&[
                                0x4b, 0xb0, 0x75, 0x35, 0xdf, 0xd5, 0x8e, 0x0b, 0x3c, 0xd6, 0x4f, 0xd7, 0x15, 0x52,
                                0x80, 0x87, 0x2a, 0x04, 0x71, 0xbc, 0xf8, 0x30, 0x95, 0x52, 0x6a, 0xce, 0x0e, 0x38,
                                0xc6, 0x00, 0x00, 0x00,
                            ]),
                            index: 0xffffffff,
                        },
                        signature_script: vec![],
                        sequence: u64::MAX,
                        sig_op_count: 0,
                        utxo_entry: None,
                    }),
                ],
                vec![],
                0,
                SUBNETWORK_ID_NATIVE,
                0,
                vec![],
                0,
                0,
            ),
            Transaction::new(
                0,
                vec![Arc::new(TransactionInput {
                    previous_outpoint: TransactionOutpoint {
                        transaction_id: TransactionId::from_slice(&[
                            0x03, 0x2e, 0x38, 0xe9, 0xc0, 0xa8, 0x4c, 0x60, 0x46, 0xd6, 0x87, 0xd1, 0x05, 0x56, 0xdc,
                            0xac, 0xc4, 0x1d, 0x27, 0x5e, 0xc5, 0x5f, 0xc0, 0x07, 0x79, 0xac, 0x88, 0xfd, 0xf3, 0x57,
                            0xa1, 0x87,
                        ]),
                        index: 0,
                    },
                    signature_script: vec![
                        0x49, // OP_DATA_73
                        0x30, 0x46, 0x02, 0x21, 0x00, 0xc3, 0x52, 0xd3, 0xdd, 0x99, 0x3a, 0x98, 0x1b, 0xeb, 0xa4, 0xa6,
                        0x3a, 0xd1, 0x5c, 0x20, 0x92, 0x75, 0xca, 0x94, 0x70, 0xab, 0xfc, 0xd5, 0x7d, 0xa9, 0x3b, 0x58,
                        0xe4, 0xeb, 0x5d, 0xce, 0x82, 0x02, 0x21, 0x00, 0x84, 0x07, 0x92, 0xbc, 0x1f, 0x45, 0x60, 0x62,
                        0x81, 0x9f, 0x15, 0xd3, 0x3e, 0xe7, 0x05, 0x5c, 0xf7, 0xb5, 0xee, 0x1a, 0xf1, 0xeb, 0xcc, 0x60,
                        0x28, 0xd9, 0xcd, 0xb1, 0xc3, 0xaf, 0x77, 0x48, 0x01, // 73-byte signature
                        0x41, // OP_DATA_65
                        0x04, 0xf4, 0x6d, 0xb5, 0xe9, 0xd6, 0x1a, 0x9d, 0xc2, 0x7b, 0x8d, 0x64, 0xad, 0x23, 0xe7, 0x38,
                        0x3a, 0x4e, 0x6c, 0xa1, 0x64, 0x59, 0x3c, 0x25, 0x27, 0xc0, 0x38, 0xc0, 0x85, 0x7e, 0xb6, 0x7e,
                        0xe8, 0xe8, 0x25, 0xdc, 0xa6, 0x50, 0x46, 0xb8, 0x2c, 0x93, 0x31, 0x58, 0x6c, 0x82, 0xe0, 0xfd,
                        0x1f, 0x63, 0x3f, 0x25, 0xf8, 0x7c, 0x16, 0x1b, 0xc6, 0xf8, 0xa6, 0x30, 0x12, 0x1d, 0xf2, 0xb3,
                        0xd3, // 65-byte pubkey
                    ],
                    sequence: u64::MAX,
                    sig_op_count: 0,
                    utxo_entry: None,
                })],
                vec![
                    Arc::new(TransactionOutput {
                        value: 0x2123e300,
                        script_public_key: Arc::new(ScriptPublicKey {
                            script: vec![
                                0x76, // OP_DUP
                                0xa9, // OP_HASH160
                                0x14, // OP_DATA_20
                                0xc3, 0x98, 0xef, 0xa9, 0xc3, 0x92, 0xba, 0x60, 0x13, 0xc5, 0xe0, 0x4e, 0xe7, 0x29,
                                0x75, 0x5e, 0xf7, 0xf5, 0x8b, 0x32, 0x88, // OP_EQUALVERIFY
                                0xac, // OP_CHECKSIG
                            ],
                            version: 0,
                        }),
                    }),
                    Arc::new(TransactionOutput {
                        value: 0x108e20f00,
                        script_public_key: Arc::new(ScriptPublicKey {
                            script: vec![
                                0x76, // OP_DUP
                                0xa9, // OP_HASH160
                                0x14, // OP_DATA_20
                                0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c,
                                0x2f, 0x6b, 0x52, 0xde, 0x3d, 0x7c, 0x88, // OP_EQUALVERIFY
                                0xac, // OP_CHECKSIG
                            ],
                            version: 0,
                        }),
                    }),
                ],
                0,
                SUBNETWORK_ID_NATIVE,
                0,
                vec![],
                0,
                0,
            ),
            Transaction::new(
                0,
                vec![Arc::new(TransactionInput {
                    previous_outpoint: TransactionOutpoint {
                        transaction_id: TransactionId::from_slice(&[
                            0xc3, 0x3e, 0xbf, 0xf2, 0xa7, 0x09, 0xf1, 0x3d, 0x9f, 0x9a, 0x75, 0x69, 0xab, 0x16, 0xa3,
                            0x27, 0x86, 0xaf, 0x7d, 0x7e, 0x2d, 0xe0, 0x92, 0x65, 0xe4, 0x1c, 0x61, 0xd0, 0x78, 0x29,
                            0x4e, 0xcf,
                        ]),
                        index: 1,
                    },
                    signature_script: vec![
                        0x47, // OP_DATA_71
                        0x30, 0x44, 0x02, 0x20, 0x03, 0x2d, 0x30, 0xdf, 0x5e, 0xe6, 0xf5, 0x7f, 0xa4, 0x6c, 0xdd, 0xb5,
                        0xeb, 0x8d, 0x0d, 0x9f, 0xe8, 0xde, 0x6b, 0x34, 0x2d, 0x27, 0x94, 0x2a, 0xe9, 0x0a, 0x32, 0x31,
                        0xe0, 0xba, 0x33, 0x3e, 0x02, 0x20, 0x3d, 0xee, 0xe8, 0x06, 0x0f, 0xdc, 0x70, 0x23, 0x0a, 0x7f,
                        0x5b, 0x4a, 0xd7, 0xd7, 0xbc, 0x3e, 0x62, 0x8c, 0xbe, 0x21, 0x9a, 0x88, 0x6b, 0x84, 0x26, 0x9e,
                        0xae, 0xb8, 0x1e, 0x26, 0xb4, 0xfe, 0x01, 0x41, // OP_DATA_65
                        0x04, 0xae, 0x31, 0xc3, 0x1b, 0xf9, 0x12, 0x78, 0xd9, 0x9b, 0x83, 0x77, 0xa3, 0x5b, 0xbc, 0xe5,
                        0xb2, 0x7d, 0x9f, 0xff, 0x15, 0x45, 0x68, 0x39, 0xe9, 0x19, 0x45, 0x3f, 0xc7, 0xb3, 0xf7, 0x21,
                        0xf0, 0xba, 0x40, 0x3f, 0xf9, 0x6c, 0x9d, 0xee, 0xb6, 0x80, 0xe5, 0xfd, 0x34, 0x1c, 0x0f, 0xc3,
                        0xa7, 0xb9, 0x0d, 0xa4, 0x63, 0x1e, 0xe3, 0x95, 0x60, 0x63, 0x9d, 0xb4, 0x62, 0xe9, 0xcb, 0x85,
                        0x0f, // 65-byte pubkey
                    ],
                    sequence: u64::MAX,
                    sig_op_count: 0,
                    utxo_entry: None,
                })],
                vec![
                    Arc::new(TransactionOutput {
                        value: 0xf4240,
                        script_public_key: Arc::new(ScriptPublicKey {
                            script: vec![
                                0x76, // OP_DUP
                                0xa9, // OP_HASH160
                                0x14, // OP_DATA_20
                                0xb0, 0xdc, 0xbf, 0x97, 0xea, 0xbf, 0x44, 0x04, 0xe3, 0x1d, 0x95, 0x24, 0x77, 0xce,
                                0x82, 0x2d, 0xad, 0xbe, 0x7e, 0x10, 0x88, // OP_EQUALVERIFY
                                0xac, // OP_CHECKSIG
                            ],
                            version: 0,
                        }),
                    }),
                    Arc::new(TransactionOutput {
                        value: 0x11d260c0,
                        script_public_key: Arc::new(ScriptPublicKey {
                            script: vec![
                                0x76, // OP_DUP
                                0xa9, // OP_HASH160
                                0x14, // OP_DATA_20
                                0x6b, 0x12, 0x81, 0xee, 0xc2, 0x5a, 0xb4, 0xe1, 0xe0, 0x79, 0x3f, 0xf4, 0xe0, 0x8a,
                                0xb1, 0xab, 0xb3, 0x40, 0x9c, 0xd9, 0x88, // OP_EQUALVERIFY
                                0xac, // OP_CHECKSIG
                            ],
                            version: 0,
                        }),
                    }),
                ],
                0,
                SUBNETWORK_ID_NATIVE,
                0,
                vec![],
                0,
                0,
            ),
            Transaction::new(
                0,
                vec![Arc::new(TransactionInput {
                    previous_outpoint: TransactionOutpoint {
                        transaction_id: TransactionId::from_slice(&[
                            0x0b, 0x60, 0x72, 0xb3, 0x86, 0xd4, 0xa7, 0x73, 0x23, 0x52, 0x37, 0xf6, 0x4c, 0x11, 0x26,
                            0xac, 0x3b, 0x24, 0x0c, 0x84, 0xb9, 0x17, 0xa3, 0x90, 0x9b, 0xa1, 0xc4, 0x3d, 0xed, 0x5f,
                            0x51, 0xf4,
                        ]),
                        index: 0,
                    },
                    signature_script: vec![
                        0x49, // OP_DATA_73
                        0x30, 0x46, 0x02, 0x21, 0x00, 0xbb, 0x1a, 0xd2, 0x6d, 0xf9, 0x30, 0xa5, 0x1c, 0xce, 0x11, 0x0c,
                        0xf4, 0x4f, 0x7a, 0x48, 0xc3, 0xc5, 0x61, 0xfd, 0x97, 0x75, 0x00, 0xb1, 0xae, 0x5d, 0x6b, 0x6f,
                        0xd1, 0x3d, 0x0b, 0x3f, 0x4a, 0x02, 0x21, 0x00, 0xc5, 0xb4, 0x29, 0x51, 0xac, 0xed, 0xff, 0x14,
                        0xab, 0xba, 0x27, 0x36, 0xfd, 0x57, 0x4b, 0xdb, 0x46, 0x5f, 0x3e, 0x6f, 0x8d, 0xa1, 0x2e, 0x2c,
                        0x53, 0x03, 0x95, 0x4a, 0xca, 0x7f, 0x78, 0xf3, 0x01, // 73-byte signature
                        0x41, // OP_DATA_65
                        0x04, 0xa7, 0x13, 0x5b, 0xfe, 0x82, 0x4c, 0x97, 0xec, 0xc0, 0x1e, 0xc7, 0xd7, 0xe3, 0x36, 0x18,
                        0x5c, 0x81, 0xe2, 0xaa, 0x2c, 0x41, 0xab, 0x17, 0x54, 0x07, 0xc0, 0x94, 0x84, 0xce, 0x96, 0x94,
                        0xb4, 0x49, 0x53, 0xfc, 0xb7, 0x51, 0x20, 0x65, 0x64, 0xa9, 0xc2, 0x4d, 0xd0, 0x94, 0xd4, 0x2f,
                        0xdb, 0xfd, 0xd5, 0xaa, 0xd3, 0xe0, 0x63, 0xce, 0x6a, 0xf4, 0xcf, 0xaa, 0xea, 0x4e, 0xa1, 0x4f,
                        0xbb, // 65-byte pubkey
                    ],
                    sequence: u64::MAX,
                    sig_op_count: 0,
                    utxo_entry: None,
                })],
                vec![Arc::new(TransactionOutput {
                    value: 0xf4240,
                    script_public_key: Arc::new(ScriptPublicKey {
                        script: vec![
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0x39, 0xaa, 0x3d, 0x56, 0x9e, 0x06, 0xa1, 0xd7, 0x92, 0x6d, 0xc4, 0xbe, 0x11, 0x93, 0xc9,
                            0x9b, 0xf2, 0xeb, 0x9e, 0xe0, 0x88, // OP_EQUALVERIFY
                            0xac, // OP_CHECKSIG
                        ],
                        version: 0,
                    }),
                })],
                0,
                SUBNETWORK_ID_NATIVE,
                0,
                vec![],
                0,
                0,
            ),
        ];
        assert_eq!(
            calc_hash_merkle_root(txs.iter()),
            Hash::from_slice(&[
                0x86, 0x8b, 0x73, 0xcd, 0x20, 0x51, 0x23, 0x60, 0xea, 0x62, 0x99, 0x9b, 0x87, 0xf6, 0xdd, 0x8d, 0xa4,
                0x0b, 0xd7, 0xcf, 0xc6, 0x32, 0x38, 0xee, 0xd9, 0x68, 0x72, 0x1f, 0xa2, 0x51, 0xe4, 0x28,
            ])
        );
    }
}
