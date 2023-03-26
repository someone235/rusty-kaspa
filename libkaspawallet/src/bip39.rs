pub const COIN_TYPE: u64 = 111111;
pub(crate) fn default_path(is_multisig: bool) -> String {
    const SINGLE_SIGNER_PURPOSE: u8 = 44;
    // Note: this is not entirely compatible to BIP 45 since
    // BIP 45 doesn't have a coin type in its derivation path.
    const MULTISIG_PURPOSE: u8 = 45;

    let purpose = if is_multisig { MULTISIG_PURPOSE } else { SINGLE_SIGNER_PURPOSE };

    format!("m/{}'/{}'/0", purpose, COIN_TYPE)
}
