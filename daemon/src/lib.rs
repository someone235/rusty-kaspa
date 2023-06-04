use std::{fs, path::PathBuf, process::exit, str::FromStr, sync::Arc};

use async_channel::unbounded;
use kaspa_consensus_core::{
    config::{Config, ConfigBuilder},
    errors::config::{ConfigError, ConfigResult},
    networktype::NetworkType,
};
use kaspa_consensus_notify::root::ConsensusNotificationRoot;
use kaspa_core::kaspad_env::version;
use kaspa_core::{core::Core, info};
use kaspa_utils::networking::ContextualNetAddress;

use kaspa_addressmanager::AddressManager;
use kaspa_consensus::consensus::factory::Factory as ConsensusFactory;
use kaspa_consensus::pipeline::monitor::ConsensusMonitor;
use kaspa_consensus::pipeline::ProcessingCounters;
use kaspa_consensus_notify::service::NotifyService;
use kaspa_consensusmanager::ConsensusManager;
use kaspa_core::{signals::Signals, task::runtime::AsyncRuntime};
use kaspa_index_processor::service::IndexService;
use kaspa_mining::manager::MiningManager;
use kaspa_p2p_flows::flow_context::FlowContext;
use kaspa_rpc_service::RpcCoreServer;

use kaspa_grpc_server::GrpcServer;
use kaspa_p2p_flows::service::P2pService;
use kaspa_utxoindex::UtxoIndex;
use kaspa_wrpc_server::service::{Options as WrpcServerOptions, WrpcEncoding, WrpcService};

const DEFAULT_DATA_DIR: &str = "datadir";
const CONSENSUS_DB: &str = "consensus";
const UTXOINDEX_DB: &str = "utxoindex";
const META_DB: &str = "meta";
const DEFAULT_LOG_DIR: &str = "logs";

fn get_home_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    return dirs::data_local_dir().unwrap();
    #[cfg(not(target_os = "windows"))]
    return dirs::home_dir().unwrap();
}

fn get_app_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    return get_home_dir().join("rusty-kaspa");
    #[cfg(not(target_os = "windows"))]
    return get_home_dir().join(".rusty-kaspa");
}

#[derive(Debug)]
pub struct Args {
    // NOTE: it is best if property names match config file fields
    pub appdir: Option<String>,
    pub logdir: Option<String>,
    pub no_log_files: bool,
    pub rpclisten: Option<ContextualNetAddress>,
    pub rpclisten_borsh: Option<ContextualNetAddress>,
    pub rpclisten_json: Option<ContextualNetAddress>,
    pub unsafe_rpc: bool,
    pub wrpc_verbose: bool,
    pub log_level: String,
    pub async_threads: usize,
    pub connect_peers: Vec<ContextualNetAddress>,
    pub add_peers: Vec<ContextualNetAddress>,
    pub listen: Option<ContextualNetAddress>,
    pub user_agent_comments: Vec<String>,
    pub utxoindex: bool,
    pub reset_db: bool,
    pub outbound_target: usize,
    pub inbound_limit: usize,
    pub enable_unsynced_mining: bool,
    pub testnet: bool,
    pub devnet: bool,
    pub simnet: bool,
    pub archival: bool,
    pub sanity: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            appdir: Some("datadir".into()),
            no_log_files: false,
            rpclisten_borsh: Some(ContextualNetAddress::from_str("127.0.0.1:17110").unwrap()),
            rpclisten_json: Some(ContextualNetAddress::from_str("127.0.0.1:18110").unwrap()),
            unsafe_rpc: false,
            async_threads: num_cpus::get(),
            utxoindex: false,
            reset_db: false,
            outbound_target: 8,
            inbound_limit: 128,
            enable_unsynced_mining: false,
            testnet: false,
            devnet: false,
            simnet: false,
            archival: false,
            sanity: false,
            logdir: Some("".into()),
            rpclisten: None,
            wrpc_verbose: false,
            log_level: "INFO".into(),
            connect_peers: vec![],
            add_peers: vec![],
            listen: None,
            user_agent_comments: vec![],
        }
    }
}

impl Args {
    pub fn apply_to_config(&self, config: &mut Config) {
        config.utxoindex = self.utxoindex;
        config.unsafe_rpc = self.unsafe_rpc;
        config.enable_unsynced_mining = self.enable_unsynced_mining;
        config.is_archival = self.archival;
        // TODO: change to `config.enable_sanity_checks = self.sanity` when we reach stable versions
        config.enable_sanity_checks = true;
        config.user_agent_comments = self.user_agent_comments.clone();
    }
}

fn validate_config_and_args(_config: &Arc<Config>, args: &Args) -> ConfigResult<()> {
    if !args.connect_peers.is_empty() && !args.add_peers.is_empty() {
        return Err(ConfigError::MixedConnectAndAddPeers);
    }
    if args.logdir.is_some() && args.no_log_files {
        return Err(ConfigError::MixedLogDirAndNoLogFiles);
    }
    Ok(())
}

pub fn create_daemon(args: Args) -> Arc<Core> {
    // Configure the panic behavior
    kaspa_core::panic::configure_panic();

    let network_type = match (args.testnet, args.devnet, args.simnet) {
        (false, false, false) => NetworkType::Mainnet,
        (true, false, false) => NetworkType::Testnet,
        (false, true, false) => NetworkType::Devnet,
        (false, false, true) => NetworkType::Simnet,
        _ => panic!("only a single net should be activated"),
    };

    let config = Arc::new(ConfigBuilder::new(network_type.into()).apply_args(|config| args.apply_to_config(config)).build());

    // Make sure config and args form a valid set of properties
    if let Err(err) = validate_config_and_args(&config, &args) {
        println!("{}", err);
        exit(1);
    }

    // TODO: Refactor all this quick-and-dirty code
    let app_dir = args
        .appdir
        .unwrap_or_else(|| get_app_dir().as_path().to_str().unwrap().to_string())
        .replace('~', get_home_dir().as_path().to_str().unwrap());
    let app_dir = if app_dir.is_empty() { get_app_dir() } else { PathBuf::from(app_dir) };
    let db_dir = app_dir.join(config.network_name()).join(DEFAULT_DATA_DIR);

    // Logs directory is usually under the application directory, unless otherwise specified
    let log_dir = args.logdir.unwrap_or_default().replace('~', get_home_dir().as_path().to_str().unwrap());
    let log_dir = if log_dir.is_empty() { app_dir.join(config.network_name()).join(DEFAULT_LOG_DIR) } else { PathBuf::from(log_dir) };
    let log_dir = if args.no_log_files { None } else { log_dir.to_str() };

    // Initialize the logger
    kaspa_core::log::init_logger(log_dir, &args.log_level);

    // Print package name and version
    info!("{} v{}", env!("CARGO_PKG_NAME"), version());

    assert!(!db_dir.to_str().unwrap().is_empty());
    info!("Application directory: {}", app_dir.display());
    info!("Data directory: {}", db_dir.display());
    match log_dir {
        Some(s) => {
            info!("Logs directory: {}", s);
        }
        None => {
            info!("Logs to console only");
        }
    }

    let consensus_db_dir = db_dir.join(CONSENSUS_DB);
    let utxoindex_db_dir = db_dir.join(UTXOINDEX_DB);
    let meta_db_dir = db_dir.join(META_DB);

    if args.reset_db && db_dir.exists() {
        // TODO: add prompt that validates the choice (unless you pass -y)
        info!("Deleting databases");
        fs::remove_dir_all(db_dir).unwrap();
    }

    fs::create_dir_all(consensus_db_dir.as_path()).unwrap();
    fs::create_dir_all(meta_db_dir.as_path()).unwrap();
    if args.utxoindex {
        info!("Utxoindex Data directory {}", utxoindex_db_dir.display());
        fs::create_dir_all(utxoindex_db_dir.as_path()).unwrap();
    }

    // DB used for addresses store and for multi-consensus management
    let meta_db = kaspa_database::prelude::open_db(meta_db_dir, true, 1);

    let connect_peers = args.connect_peers.iter().map(|x| x.normalize(config.default_p2p_port())).collect::<Vec<_>>();
    let add_peers = args.add_peers.iter().map(|x| x.normalize(config.default_p2p_port())).collect();
    let p2p_server_addr = args.listen.unwrap_or(ContextualNetAddress::unspecified()).normalize(config.default_p2p_port());
    // connect_peers means no DNS seeding and no outbound peers
    let outbound_target = if connect_peers.is_empty() { args.outbound_target } else { 0 };
    let dns_seeders = if connect_peers.is_empty() { config.dns_seeders } else { &[] };

    let grpc_server_addr = args.rpclisten.unwrap_or(ContextualNetAddress::unspecified()).normalize(config.default_rpc_port());

    let core = Arc::new(Core::new());

    // ---

    let (notification_send, notification_recv) = unbounded();
    let notification_root = Arc::new(ConsensusNotificationRoot::new(notification_send));
    let counters = Arc::new(ProcessingCounters::default());

    // Use `num_cpus` background threads for the consensus database as recommended by rocksdb
    let consensus_db_parallelism = num_cpus::get();
    let consensus_factory = Arc::new(ConsensusFactory::new(
        meta_db.clone(),
        &config,
        consensus_db_dir,
        consensus_db_parallelism,
        notification_root.clone(),
        counters.clone(),
    ));
    let consensus_manager = Arc::new(ConsensusManager::new(consensus_factory));
    let monitor = Arc::new(ConsensusMonitor::new(counters));

    let notify_service = Arc::new(NotifyService::new(notification_root.clone(), notification_recv));
    let index_service: Option<Arc<IndexService>> = if args.utxoindex {
        // Use only a single thread for none-consensus databases
        let utxoindex_db = kaspa_database::prelude::open_db(utxoindex_db_dir, true, 1);
        let utxoindex = UtxoIndex::new(consensus_manager.clone(), utxoindex_db).unwrap();
        let index_service = Arc::new(IndexService::new(&notify_service.notifier(), Some(utxoindex)));
        Some(index_service)
    } else {
        None
    };

    let address_manager = AddressManager::new(meta_db);
    let mining_manager = Arc::new(MiningManager::new(config.target_time_per_block, false, config.max_block_mass, None));

    let flow_context = Arc::new(FlowContext::new(
        consensus_manager.clone(),
        address_manager,
        config.clone(),
        mining_manager.clone(),
        notification_root,
    ));
    let p2p_service = Arc::new(P2pService::new(
        flow_context.clone(),
        connect_peers,
        add_peers,
        p2p_server_addr,
        outbound_target,
        args.inbound_limit,
        dns_seeders,
        config.default_p2p_port(),
    ));

    let rpc_core_server = Arc::new(RpcCoreServer::new(
        consensus_manager.clone(),
        notify_service.notifier(),
        index_service.as_ref().map(|x| x.notifier()),
        mining_manager,
        flow_context,
        index_service.as_ref().map(|x| x.utxoindex().unwrap()),
        config,
        core.clone(),
    ));
    let grpc_server = Arc::new(GrpcServer::new(grpc_server_addr, rpc_core_server.service()));

    // Create an async runtime and register the top-level async services
    let async_runtime = Arc::new(AsyncRuntime::new(args.async_threads));
    async_runtime.register(notify_service);
    if let Some(index_service) = index_service {
        async_runtime.register(index_service)
    };
    async_runtime.register(rpc_core_server.clone());
    async_runtime.register(grpc_server);
    async_runtime.register(p2p_service);
    async_runtime.register(monitor);

    let wrpc_service_tasks: usize = 2; // num_cpus::get() / 2;
                                       // Register wRPC servers based on command line arguments
    [(args.rpclisten_borsh, WrpcEncoding::Borsh), (args.rpclisten_json, WrpcEncoding::SerdeJson)]
        .iter()
        .filter_map(|(listen_address, encoding)| {
            listen_address.as_ref().map(|listen_address| {
                Arc::new(WrpcService::new(
                    wrpc_service_tasks,
                    Some(rpc_core_server.service()),
                    encoding,
                    WrpcServerOptions {
                        listen_address: listen_address.to_string(), // TODO: use a normalized ContextualNetAddress instead of a String
                        verbose: args.wrpc_verbose,
                        ..WrpcServerOptions::default()
                    },
                ))
            })
        })
        .for_each(|server| async_runtime.register(server));

    // Bind the keyboard signal to the core
    Arc::new(Signals::new(&core)).init();

    // Consensus must start first in order to init genesis in stores
    core.bind(consensus_manager);
    core.bind(async_runtime);

    core
}
