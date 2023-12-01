use indexmap::IndexMap;
use parking_lot::{RwLock, RwLockReadGuard};
use rand::Rng;
use std::{
    collections::{hash_map::RandomState, HashSet},
    hash::BuildHasher,
    sync::Arc,
};

#[derive(Default, Debug)]
pub struct ReadLock<T>(Arc<RwLock<T>>);

impl<T> ReadLock<T> {
    pub fn new(rwlock: Arc<RwLock<T>>) -> Self {
        Self(rwlock)
    }

    pub fn read(&self) -> RwLockReadGuard<T> {
        self.0.read()
    }
}

impl<T> From<T> for ReadLock<T> {
    fn from(value: T) -> Self {
        Self::new(Arc::new(RwLock::new(value)))
    }
}

#[derive(Clone)]
pub struct SetCache<
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + std::hash::Hash + Eq,
    S = RandomState,
    W = RandomState,
> {
    // We use IndexMap and not HashMap, because it makes it cheaper to remove a random element when the cache is full.
    #[allow(clippy::type_complexity)]
    map: Arc<RwLock<IndexMap<TKey, Arc<RwLock<HashSet<TData, W>>>, S>>>,
    size: usize,
}

impl<
        TKey: Clone + std::hash::Hash + Eq + Send + Sync,
        TData: Clone + Send + Sync + std::hash::Hash + Eq,
        S: BuildHasher + Default,
        W: BuildHasher + Default,
    > SetCache<TKey, TData, S, W>
{
    pub fn new(size: u64) -> Self {
        Self { map: Arc::new(RwLock::new(IndexMap::with_capacity_and_hasher(size as usize, S::default()))), size: size as usize }
    }

    pub fn get(&self, key: &TKey) -> Option<ReadLock<HashSet<TData, W>>> {
        self.map.read().get(key).cloned().map(ReadLock)
    }

    pub fn contains_key(&self, key: &TKey) -> bool {
        self.map.read().contains_key(key)
    }

    pub fn insert(&self, key: TKey, set: HashSet<TData, W>) -> ReadLock<HashSet<TData, W>> {
        let set = Arc::new(RwLock::new(set));
        if self.size == 0 {
            return ReadLock(set);
        }
        let mut write_guard = self.map.write();
        // TODO: implement set counting and limit the overall number of elements in all sets combined
        // This means cache size needs to be checked also within `append_if_entry_exists`
        if write_guard.len() == self.size {
            write_guard.swap_remove_index(rand::thread_rng().gen_range(0..self.size));
        }
        write_guard.insert(key, set.clone());
        ReadLock(set)
    }

    pub fn append_if_entry_exists(&self, key: TKey, data: TData) {
        if self.size == 0 {
            return;
        }
        let mut write_guard = self.map.write();
        if let Some(e) = write_guard.get_mut(&key) {
            e.write().insert(data);
        }
        // TODO: check here for cache size when implementing set counting
    }

    pub fn remove_if_entry_exists(&self, key: TKey, data: TData) {
        if self.size == 0 {
            return;
        }
        let mut write_guard = self.map.write();
        if let Some(e) = write_guard.get_mut(&key) {
            e.write().remove(&data);
        }
    }

    pub fn remove(&self, key: &TKey) {
        if self.size == 0 {
            return;
        }
        let mut write_guard = self.map.write();
        write_guard.swap_remove(key);
    }

    pub fn remove_many(&self, key_iter: &mut impl Iterator<Item = TKey>) {
        if self.size == 0 {
            return;
        }
        let mut write_guard = self.map.write();
        for key in key_iter {
            write_guard.swap_remove(&key);
        }
    }

    pub fn remove_all(&self) {
        if self.size == 0 {
            return;
        }
        let mut write_guard = self.map.write();
        write_guard.clear()
    }
}
