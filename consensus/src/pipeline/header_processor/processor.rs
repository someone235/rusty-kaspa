use crate::{
    errors::{BlockProcessResult, RuleError},
    model::{
        services::{reachability::MTReachabilityService, relations::MTRelationsService},
        stores::{
            block_window_cache::{BlockWindowCacheStore, BlockWindowHeap},
            daa::DbDaaStore,
            depth::DbDepthStore,
            errors::StoreResultExtensions,
            ghostdag::{DbGhostdagStore, GhostdagData, GhostdagStoreReader},
            headers::DbHeadersStore,
            headers_selected_tip::{DbHeadersSelectedTipStore, HeadersSelectedTipStoreReader},
            past_pruning_points::DbPastPruningPointsStore,
            pruning::{DbPruningStore, PruningPointInfo, PruningStore, PruningStoreReader},
            reachability::{DbReachabilityStore, ReachabilityStoreReader, StagingReachabilityStore},
            relations::{DbRelationsStore, RelationsStoreReader},
            statuses::{DbStatusesStore, StatusesStore, StatusesStoreBatchExtensions, StatusesStoreReader},
            DB,
        },
    },
    params::Params,
    pipeline::deps_manager::{BlockTask, BlockTaskDependencyManager},
    processes::{
        block_depth::BlockDepthManager,
        difficulty::DifficultyManager,
        ghostdag::{ordering::SortableBlock, protocol::GhostdagManager},
        parents_builder::ParentsManager,
        past_median_time::PastMedianTimeManager,
        pruning::PruningManager,
        reachability::inquirer as reachability,
        traversal_manager::DagTraversalManager,
    },
    test_helpers::header_from_precomputed_hash,
};
use consensus_core::{
    blockhash::{BlockHashExtensions, BlockHashes, ORIGIN},
    blockstatus::BlockStatus::{self, StatusHeaderOnly, StatusInvalid},
    header::Header,
    BlockHashSet, BlockLevel,
};
use crossbeam_channel::{Receiver, Sender};
use hashes::Hash;
use itertools::Itertools;
use parking_lot::RwLock;
use rayon::ThreadPool;
use rocksdb::WriteBatch;
use std::sync::{atomic::Ordering, Arc};

use super::super::ProcessingCounters;

pub struct HeaderProcessingContext<'a> {
    pub hash: Hash,
    pub header: &'a Arc<Header>,
    pub pruning_info: PruningPointInfo,
    pub non_pruned_parents: Vec<BlockHashes>,

    // Staging data
    pub ghostdag_data: Option<Vec<Arc<GhostdagData>>>,
    pub block_window_for_difficulty: Option<BlockWindowHeap>,
    pub block_window_for_past_median_time: Option<BlockWindowHeap>,
    pub mergeset_non_daa: Option<BlockHashSet>,
    pub merge_depth_root: Option<Hash>,
    pub finality_point: Option<Hash>,
    pub block_level: Option<BlockLevel>,
}

impl<'a> HeaderProcessingContext<'a> {
    pub fn new(hash: Hash, header: &'a Arc<Header>, pruning_info: PruningPointInfo, non_pruned_parents: Vec<BlockHashes>) -> Self {
        Self {
            hash,
            header,
            pruning_info,
            non_pruned_parents,
            ghostdag_data: None,
            block_window_for_difficulty: None,
            mergeset_non_daa: None,
            block_window_for_past_median_time: None,
            merge_depth_root: None,
            finality_point: None,
            block_level: None,
        }
    }

    pub fn get_non_pruned_parents(&mut self) -> BlockHashes {
        self.non_pruned_parents[0].clone()
    }

    pub fn pruning_point(&self) -> Hash {
        self.pruning_info.pruning_point
    }

    pub fn get_ghostdag_data(&self) -> Option<Arc<GhostdagData>> {
        Some(self.ghostdag_data.as_ref()?[0].clone())
    }
}

pub struct HeaderProcessor {
    // Channels
    receiver: Receiver<BlockTask>,
    body_sender: Sender<BlockTask>,

    // Thread pool
    pub(super) thread_pool: Arc<ThreadPool>,

    // Config
    pub(super) genesis_hash: Hash,
    pub(super) genesis_timestamp: u64,
    pub(super) genesis_bits: u32,
    pub(super) timestamp_deviation_tolerance: u64,
    pub(super) target_time_per_block: u64,
    pub(super) max_block_parents: u8,
    pub(super) difficulty_window_size: usize,
    pub(super) mergeset_size_limit: u64,
    pub(super) skip_proof_of_work: bool,
    pub(super) max_block_level: BlockLevel,
    process_genesis: bool,

    // DB
    db: Arc<DB>,

    // Stores
    relations_stores: Arc<RwLock<Vec<DbRelationsStore>>>,
    reachability_store: Arc<RwLock<DbReachabilityStore>>,
    ghostdag_stores: Vec<Arc<DbGhostdagStore>>,
    pub(super) statuses_store: Arc<RwLock<DbStatusesStore>>,
    pub(super) pruning_store: Arc<RwLock<DbPruningStore>>,
    pub(super) block_window_cache_for_difficulty: Arc<BlockWindowCacheStore>,
    pub(super) block_window_cache_for_past_median_time: Arc<BlockWindowCacheStore>,
    pub(super) daa_store: Arc<DbDaaStore>,
    pub(super) headers_store: Arc<DbHeadersStore>,
    pub(super) headers_selected_tip_store: Arc<RwLock<DbHeadersSelectedTipStore>>,
    depth_store: Arc<DbDepthStore>,

    // Managers and services
    ghostdag_managers: Vec<
        GhostdagManager<
            DbGhostdagStore,
            MTRelationsService<DbRelationsStore>,
            MTReachabilityService<DbReachabilityStore>,
            DbHeadersStore,
        >,
    >,
    pub(super) dag_traversal_manager: DagTraversalManager<DbGhostdagStore, BlockWindowCacheStore>,
    pub(super) difficulty_manager: DifficultyManager<DbHeadersStore>,
    pub(super) past_median_time_manager: PastMedianTimeManager<DbHeadersStore, DbGhostdagStore, BlockWindowCacheStore>,
    pub(super) depth_manager: BlockDepthManager<DbDepthStore, DbReachabilityStore, DbGhostdagStore>,
    pub(super) reachability_service: MTReachabilityService<DbReachabilityStore>,
    pub(super) pruning_manager: PruningManager<DbGhostdagStore, DbReachabilityStore, DbHeadersStore, DbPastPruningPointsStore>,
    pub(super) parents_manager: ParentsManager<DbHeadersStore, DbReachabilityStore, DbRelationsStore>,

    // Dependency manager
    task_manager: BlockTaskDependencyManager,

    // Counters
    counters: Arc<ProcessingCounters>,
}

impl HeaderProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: Receiver<BlockTask>,
        body_sender: Sender<BlockTask>,
        thread_pool: Arc<ThreadPool>,
        params: &Params,
        process_genesis: bool,
        db: Arc<DB>,
        relations_stores: Arc<RwLock<Vec<DbRelationsStore>>>,
        reachability_store: Arc<RwLock<DbReachabilityStore>>,
        ghostdag_stores: Vec<Arc<DbGhostdagStore>>,
        headers_store: Arc<DbHeadersStore>,
        daa_store: Arc<DbDaaStore>,
        statuses_store: Arc<RwLock<DbStatusesStore>>,
        pruning_store: Arc<RwLock<DbPruningStore>>,
        depth_store: Arc<DbDepthStore>,
        headers_selected_tip_store: Arc<RwLock<DbHeadersSelectedTipStore>>,
        block_window_cache_for_difficulty: Arc<BlockWindowCacheStore>,
        block_window_cache_for_past_median_time: Arc<BlockWindowCacheStore>,
        reachability_service: MTReachabilityService<DbReachabilityStore>,
        past_median_time_manager: PastMedianTimeManager<DbHeadersStore, DbGhostdagStore, BlockWindowCacheStore>,
        dag_traversal_manager: DagTraversalManager<DbGhostdagStore, BlockWindowCacheStore>,
        difficulty_manager: DifficultyManager<DbHeadersStore>,
        depth_manager: BlockDepthManager<DbDepthStore, DbReachabilityStore, DbGhostdagStore>,
        pruning_manager: PruningManager<DbGhostdagStore, DbReachabilityStore, DbHeadersStore, DbPastPruningPointsStore>,
        parents_manager: ParentsManager<DbHeadersStore, DbReachabilityStore, DbRelationsStore>,
        ghostdag_managers: Vec<
            GhostdagManager<
                DbGhostdagStore,
                MTRelationsService<DbRelationsStore>,
                MTReachabilityService<DbReachabilityStore>,
                DbHeadersStore,
            >,
        >,
        counters: Arc<ProcessingCounters>,
    ) -> Self {
        Self {
            receiver,
            body_sender,
            thread_pool,
            genesis_hash: params.genesis_hash,
            genesis_timestamp: params.genesis_timestamp,
            difficulty_window_size: params.difficulty_window_size,
            db,
            relations_stores,
            reachability_store,
            ghostdag_stores,
            statuses_store,
            pruning_store,
            daa_store,
            headers_store,
            depth_store,
            headers_selected_tip_store,
            block_window_cache_for_difficulty,
            block_window_cache_for_past_median_time,
            ghostdag_managers,
            dag_traversal_manager,
            difficulty_manager,
            reachability_service,
            past_median_time_manager,
            depth_manager,
            pruning_manager,
            parents_manager,
            task_manager: BlockTaskDependencyManager::new(),
            counters,
            timestamp_deviation_tolerance: params.timestamp_deviation_tolerance,
            target_time_per_block: params.target_time_per_block,
            max_block_parents: params.max_block_parents,
            mergeset_size_limit: params.mergeset_size_limit,
            genesis_bits: params.genesis_bits,
            skip_proof_of_work: params.skip_proof_of_work,
            max_block_level: params.max_block_level,
            process_genesis,
        }
    }

    pub fn worker(self: &Arc<HeaderProcessor>) {
        while let Ok(task) = self.receiver.recv() {
            match task {
                BlockTask::Exit => break,
                BlockTask::Process(block, result_transmitters) => {
                    let hash = block.block.header.hash;
                    if self.task_manager.register(block, result_transmitters) {
                        let processor = self.clone();
                        self.thread_pool.spawn(move || {
                            processor.queue_block(hash);
                        });
                    }
                }
            };
        }

        // Wait until all workers are idle before exiting
        self.task_manager.wait_for_idle();

        // Pass the exit signal on to the following processor
        self.body_sender.send(BlockTask::Exit).unwrap();
    }

    fn queue_block(self: &Arc<HeaderProcessor>, hash: Hash) {
        if let Some(block) = self.task_manager.try_begin(hash) {
            let res = self.process_header(&block.block.header, block.ghostdag_data);

            let dependent_tasks = self.task_manager.end(hash, |block, result_transmitters| {
                if res.is_err() || block.block.is_header_only() {
                    for transmitter in result_transmitters {
                        // We don't care if receivers were dropped
                        let _ = transmitter.send(res.clone());
                    }
                } else {
                    self.body_sender.send(BlockTask::Process(block, result_transmitters)).unwrap();
                }
            });

            for dep in dependent_tasks {
                let processor = self.clone();
                self.thread_pool.spawn(move || processor.queue_block(dep));
            }
        }
    }

    fn header_was_processed(self: &Arc<HeaderProcessor>, hash: Hash) -> bool {
        self.statuses_store.read().has(hash).unwrap()
    }

    fn process_header(
        self: &Arc<HeaderProcessor>,
        header: &Arc<Header>,
        ghostdag_data_option: Option<Arc<GhostdagData>>,
    ) -> BlockProcessResult<BlockStatus> {
        let is_trusted = ghostdag_data_option.is_some();
        let status_option = self.statuses_store.read().get(header.hash).unwrap_option();

        match status_option {
            Some(StatusInvalid) => return Err(RuleError::KnownInvalid),
            Some(status) => return Ok(status),
            None => {}
        }

        // Create processing context
        let is_genesis = header.direct_parents().is_empty();
        let pruning_point = self.pruning_store.read().get().unwrap();
        let relations_read = self.relations_stores.read();
        let non_pruned_parents = (0..=self.max_block_level)
            .map(|level| {
                Arc::new(if is_genesis {
                    vec![ORIGIN]
                } else {
                    let filtered = self
                        .parents_manager
                        .parents_at_level(header, level)
                        .iter()
                        .copied()
                        .filter(|parent| {
                            // self.ghostdag_stores[level as usize].has(*parent).unwrap()
                            relations_read[level as usize].has(*parent).unwrap()
                        })
                        .collect_vec();
                    if filtered.is_empty() {
                        vec![ORIGIN]
                    } else {
                        filtered
                    }
                })
            })
            .collect_vec();
        drop(relations_read);
        let mut ctx = HeaderProcessingContext::new(header.hash, header, pruning_point, non_pruned_parents);
        if is_trusted {
            ctx.mergeset_non_daa = Some(Default::default()); // TODO: Check that it's fine for coinbase calculations.
        }

        // Run all header validations for the new header
        self.pre_ghostdag_validation(&mut ctx, header, is_trusted)?;
        let ghostdag_data = (0..=ctx.block_level.unwrap())
            .map(|level| {
                if let Some(gd) = self.ghostdag_stores[level as usize].get_data(ctx.hash).unwrap_option() {
                    gd
                } else {
                    Arc::new(self.ghostdag_managers[level as usize].ghostdag(&ctx.non_pruned_parents[level as usize]))
                }
            })
            .collect_vec();
        ctx.ghostdag_data = Some(ghostdag_data);
        if is_trusted {
            // let gd_data = ctx.get_ghostdag_data().unwrap();
            // let merge_depth_root = self.depth_manager.calc_merge_depth_root(&gd_data, ctx.pruning_point());
            // let finality_point = self.depth_manager.calc_finality_point(&gd_data, ctx.pruning_point());
            ctx.merge_depth_root = Some(ORIGIN);
            ctx.finality_point = Some(ORIGIN);
        }

        if !is_trusted {
            // TODO: For now we skip all validations for trusted blocks, but in the future we should
            // employ some validations to avoid spam etc.
            self.pre_pow_validation(&mut ctx, header)?;
            if let Err(e) = self.post_pow_validation(&mut ctx, header) {
                self.statuses_store.write().set(ctx.hash, StatusInvalid).unwrap();
                return Err(e);
            }
        }

        self.commit_header(ctx, header);

        // Report counters
        self.counters.header_counts.fetch_add(1, Ordering::Relaxed);
        self.counters.dep_counts.fetch_add(header.direct_parents().len() as u64, Ordering::Relaxed);
        Ok(StatusHeaderOnly)
    }

    fn commit_header(self: &Arc<HeaderProcessor>, ctx: HeaderProcessingContext, header: &Arc<Header>) {
        let ghostdag_data = ctx.ghostdag_data.unwrap();

        // Create a DB batch writer
        let mut batch = WriteBatch::default();

        // Write to append only stores: this requires no lock and hence done first
        // TODO: Insert all levels data
        for (level, datum) in ghostdag_data.iter().enumerate() {
            if self.ghostdag_stores[level].has(ctx.hash).unwrap() {
                // The data might have been already written when applying the pruning proof.
                continue;
            }
            self.ghostdag_stores[level].insert_batch(&mut batch, ctx.hash, datum).unwrap();
        }
        if let Some(window) = ctx.block_window_for_difficulty {
            self.block_window_cache_for_difficulty.insert(ctx.hash, Arc::new(window));
        }

        if let Some(window) = ctx.block_window_for_past_median_time {
            self.block_window_cache_for_past_median_time.insert(ctx.hash, Arc::new(window));
        }

        self.daa_store.insert_batch(&mut batch, ctx.hash, Arc::new(ctx.mergeset_non_daa.unwrap())).unwrap();
        if !self.headers_store.has(ctx.hash).unwrap() {
            // The data might have been already written when applying the pruning proof.
            self.headers_store.insert_batch(&mut batch, ctx.hash, ctx.header.clone(), ctx.block_level.unwrap()).unwrap();
        }
        if let Some(merge_depth_root) = ctx.merge_depth_root {
            self.depth_store.insert_batch(&mut batch, ctx.hash, merge_depth_root, ctx.finality_point.unwrap()).unwrap();
        }

        // Create staging reachability store. We use an upgradable read here to avoid concurrent
        // staging reachability operations. PERF: we assume that reachability processing time << header processing
        // time, and thus serializing this part will do no harm. However this should be benchmarked. The
        // alternative is to create a separate ReachabilityProcessor and to manage things more tightly.
        let mut staging = StagingReachabilityStore::new(self.reachability_store.upgradable_read());

        let has_reachability = staging.has(ctx.hash).unwrap();
        if !has_reachability {
            // Add block to staging reachability
            let reachability_parent = if ctx.non_pruned_parents[0].len() == 1 && ctx.non_pruned_parents[0][0].is_origin() {
                ORIGIN
            } else {
                ghostdag_data[0].selected_parent
            };

            let mut reachability_mergeset = ghostdag_data[0]
                .unordered_mergeset_without_selected_parent()
                .filter(|hash| self.reachability_store.read().has(*hash).unwrap()); // TODO: Use read lock only once
            reachability::add_block(&mut staging, ctx.hash, reachability_parent, &mut reachability_mergeset).unwrap();
        }

        // Non-append only stores need to use write locks.
        // Note we need to keep the lock write guards until the batch is written.
        let mut hst_write_guard = self.headers_selected_tip_store.write();
        let prev_hst = hst_write_guard.get().unwrap();
        if SortableBlock::new(ctx.hash, header.blue_work) > prev_hst {
            // Hint reachability about the new tip.
            reachability::hint_virtual_selected_parent(&mut staging, ctx.hash).unwrap();
            hst_write_guard.set_batch(&mut batch, SortableBlock::new(ctx.hash, header.blue_work)).unwrap();
        }

        let is_genesis = header.direct_parents().is_empty();
        let parents = (0..=ctx.block_level.unwrap()).map(|level| {
            Arc::new(if is_genesis {
                vec![ORIGIN]
            } else {
                self.parents_manager
                    .parents_at_level(ctx.header, level)
                    .iter()
                    .copied()
                    .filter(|parent| self.ghostdag_stores[level as usize].has(*parent).unwrap())
                    .collect_vec()
            })
        });

        let mut relations_write_guard = self.relations_stores.write();
        parents.enumerate().for_each(|(level, parent_by_level)| {
            if !relations_write_guard[level].has(header.hash).unwrap() {
                relations_write_guard[level].insert_batch(&mut batch, header.hash, parent_by_level).unwrap();
            }
        });

        let statuses_write_guard = self.statuses_store.set_batch(&mut batch, ctx.hash, StatusHeaderOnly).unwrap();

        // Write reachability data. Only at this brief moment the reachability store is locked for reads.
        // We take special care for this since reachability read queries are used throughout the system frequently.
        // Note we hold the lock until the batch is written
        let reachability_write_guard = staging.commit(&mut batch).unwrap();

        // Flush the batch to the DB
        self.db.write(batch).unwrap();

        // Calling the drops explicitly after the batch is written in order to avoid possible errors.
        drop(reachability_write_guard);
        drop(statuses_write_guard);
        drop(relations_write_guard);
        drop(hst_write_guard);
    }

    pub fn process_genesis_if_needed(self: &Arc<HeaderProcessor>) {
        if !self.process_genesis || self.header_was_processed(self.genesis_hash) {
            return;
        }

        {
            let mut batch = WriteBatch::default();
            let mut hst_write_guard = self.headers_selected_tip_store.write();
            hst_write_guard.set_batch(&mut batch, SortableBlock::new(self.genesis_hash, 0.into())).unwrap(); // TODO: take blue work from genesis block
            self.db.write(batch).unwrap();
            drop(hst_write_guard);
        }

        self.pruning_store.write().set(self.genesis_hash, self.genesis_hash, 0).unwrap();
        let mut header = header_from_precomputed_hash(self.genesis_hash, vec![]); // TODO
        header.bits = self.genesis_bits;
        header.timestamp = self.genesis_timestamp;
        let header = Arc::new(header);
        let mut ctx = HeaderProcessingContext::new(
            self.genesis_hash,
            &header,
            PruningPointInfo::from_genesis(self.genesis_hash),
            vec![BlockHashes::new(vec![ORIGIN])],
        );
        ctx.ghostdag_data = Some(self.ghostdag_managers.iter().map(|m| Arc::new(m.genesis_ghostdag_data())).collect());
        ctx.block_window_for_difficulty = Some(Default::default());
        ctx.block_window_for_past_median_time = Some(Default::default());
        ctx.mergeset_non_daa = Some(Default::default());
        ctx.merge_depth_root = Some(ORIGIN);
        ctx.finality_point = Some(ORIGIN);
        ctx.block_level = Some(self.max_block_level);
        self.commit_header(ctx, &header);
    }

    pub fn process_origin_if_needed(self: &Arc<HeaderProcessor>) {
        if self.relations_stores.read()[0].has(ORIGIN).unwrap() {
            return;
        }

        let mut batch = WriteBatch::default();
        let mut relations_write_guard = self.relations_stores.write();
        (0..=self.max_block_level).for_each(|level| {
            relations_write_guard[level as usize].insert_batch(&mut batch, ORIGIN, BlockHashes::new(vec![])).unwrap()
        });
        let mut hst_write_guard = self.headers_selected_tip_store.write();
        hst_write_guard.set_batch(&mut batch, SortableBlock::new(ORIGIN, 0.into())).unwrap();
        self.db.write(batch).unwrap();
        drop(hst_write_guard);
        drop(relations_write_guard);
    }
}
