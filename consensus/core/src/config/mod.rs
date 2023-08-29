pub mod bps;
pub mod constants;
pub mod genesis;
pub mod params;

use std::ops::Deref;

use kaspa_utils::networking::{ContextualNetAddress, IpAddress};

#[cfg(feature = "developer-mode")]
use crate::utxo::utxo_collection::UtxoCollection;

use {
    constants::perf::{PerfParams, PERF_PARAMS},
    params::Params,
};

/// Various consensus configurations all bundled up under a single struct. Use `Config::new` for directly building from
/// a `Params` instance. For anything more complex it is recommended to use `ConfigBuilder`. NOTE: this struct can be
/// implicitly de-refed into `Params`
#[derive(Clone, Debug)]
pub struct Config {
    /// Consensus params
    pub params: Params,
    /// Performance params
    pub perf: PerfParams,

    //
    // Additional consensus configuration arguments which are not consensus sensitive
    //
    pub process_genesis: bool,

    /// Indicates whether this node is an archival node
    pub is_archival: bool,

    /// Enable various sanity checks which might be compute-intensive (mostly performed during pruning)
    pub enable_sanity_checks: bool,

    // TODO: move non-consensus parameters like utxoindex to a higher scoped Config
    /// Enable the UTXO index
    pub utxoindex: bool,

    /// Enable RPC commands which affect the state of the node
    pub unsafe_rpc: bool,

    /// Allow the node to accept blocks from RPC while not synced
    /// (required when initiating a new network from genesis)
    pub enable_unsynced_mining: bool,

    /// Allow mainnet mining. Until a stable Beta version we keep this option off by default
    pub enable_mainnet_mining: bool,

    pub user_agent_comments: Vec<String>,

    // If undefined, sets it to 0.0.0.0
    pub p2p_listen_address: ContextualNetAddress,

    pub externalip: Option<IpAddress>,

    #[cfg(feature = "developer-mode")]
    pub initial_utxo_set: UtxoCollection,
}

impl Config {
    pub fn new(params: Params) -> Self {
        Self::with_perf(params, PERF_PARAMS)
    }

    pub fn with_perf(params: Params, perf: PerfParams) -> Self {
        Self {
            params,
            perf,
            process_genesis: true,
            is_archival: false,
            enable_sanity_checks: false,
            utxoindex: false,
            unsafe_rpc: false,
            enable_unsynced_mining: false,
            enable_mainnet_mining: false,
            user_agent_comments: Default::default(),
            externalip: None,
            p2p_listen_address: ContextualNetAddress::unspecified(),

            #[cfg(feature = "developer-mode")]
            initial_utxo_set: Default::default(),
        }
    }

    pub fn to_builder(&self) -> ConfigBuilder {
        ConfigBuilder { config: self.clone() }
    }
}

impl AsRef<Params> for Config {
    fn as_ref(&self) -> &Params {
        &self.params
    }
}

impl Deref for Config {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn new(params: Params) -> Self {
        Self { config: Config::new(params) }
    }

    pub fn set_perf_params(mut self, perf: PerfParams) -> Self {
        self.config.perf = perf;
        self
    }

    pub fn adjust_perf_params_to_consensus_params(mut self) -> Self {
        self.config.perf.adjust_to_consensus_params(&self.config.params);
        self
    }

    pub fn edit_consensus_params<F>(mut self, edit_func: F) -> Self
    where
        F: Fn(&mut Params),
    {
        edit_func(&mut self.config.params);
        self
    }

    pub fn apply_args<F>(mut self, edit_func: F) -> Self
    where
        F: Fn(&mut Config),
    {
        edit_func(&mut self.config);
        self
    }

    pub fn skip_proof_of_work(mut self) -> Self {
        self.config.params.skip_proof_of_work = true;
        self
    }

    pub fn set_archival(mut self) -> Self {
        self.config.is_archival = true;
        self
    }

    pub fn enable_sanity_checks(mut self) -> Self {
        self.config.enable_sanity_checks = true;
        self
    }

    pub fn skip_adding_genesis(mut self) -> Self {
        self.config.process_genesis = false;
        self
    }

    pub fn build(self) -> Config {
        self.config
    }
}
