use crate::{
    db::DB,
    errors::StoreError,
    set_cache::{ReadLock, SetCache},
};

use super::prelude::{DbKey, DbWriter};
use rocksdb::{IteratorMode, ReadOptions};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{hash_map::RandomState, HashSet},
    error::Error,
    hash::BuildHasher,
    sync::Arc,
};

/// A concurrent DB store for **set** access with typed caching.
#[derive(Clone)]
pub struct CachedDbSetAccess<TKey, TData, S = RandomState, W = RandomState>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + std::hash::Hash + Eq,
    W: Send + Sync,
{
    db: Arc<DB>,

    // Cache
    cache: SetCache<TKey, TData, S, W>,

    // DB bucket/path
    prefix: Vec<u8>,
}

impl<TKey, TData, S, W> CachedDbSetAccess<TKey, TData, S, W>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync + AsRef<[u8]>,
    TData: Clone + std::hash::Hash + Eq + Send + Sync + DeserializeOwned + Serialize,
    S: BuildHasher + Default + Send + Sync,
    W: BuildHasher + Default + Send + Sync,
{
    pub fn new(db: Arc<DB>, cache_size: u64, prefix: Vec<u8>) -> Self {
        Self { db, cache: SetCache::new(cache_size), prefix }
    }

    pub fn read_from_cache(&self, key: TKey) -> Option<ReadLock<HashSet<TData, W>>> {
        self.cache.get(&key)
    }

    pub fn read(&self, key: TKey) -> Result<ReadLock<HashSet<TData, W>>, StoreError> {
        if let Some(data) = self.cache.get(&key) {
            Ok(data)
        } else {
            let data: HashSet<TData, _> = self.bucket_iterator(key.clone()).map(|x| x.unwrap()).collect();
            let readonly_data = self.cache.insert(key, data);
            Ok(readonly_data)
        }
    }

    pub fn write(&self, writer: impl DbWriter, key: TKey, data: TData) -> Result<(), StoreError> {
        self.cache.append_if_entry_exists(key.clone(), data.clone());
        self.write_to_db(writer, key, &data)
    }

    fn write_to_db(&self, mut writer: impl DbWriter, key: TKey, data: &TData) -> Result<(), StoreError> {
        writer.put(self.get_db_key(&key, data)?, [])?;
        Ok(())
    }

    fn get_db_key(&self, key: &TKey, data: &TData) -> Result<DbKey, StoreError> {
        let bin_data = bincode::serialize(&data)?;
        Ok(DbKey::new_with_bucket(&self.prefix, key, bin_data))
    }

    pub fn delete_bucket(&self, mut writer: impl DbWriter, key: TKey) -> Result<(), StoreError> {
        let readonly_data = self.read(key.clone())?;
        let read_guard = readonly_data.read();
        // TODO: check if DB supports delete by prefix
        for data in read_guard.iter() {
            writer.delete(self.get_db_key(&key, data)?)?;
        }
        self.cache.remove(&key);
        Ok(())
    }

    pub fn delete(&self, mut writer: impl DbWriter, key: TKey, data: TData) -> Result<(), StoreError> {
        self.cache.remove_if_entry_exists(key.clone(), data.clone());
        writer.delete(self.get_db_key(&key, &data)?)?;
        Ok(())
    }

    fn seek_iterator(
        &self,
        key: TKey,
        limit: usize,     // amount to take.
        skip_first: bool, // skips the first value, (useful in conjunction with the seek-key, as to not re-retrieve).
    ) -> impl Iterator<Item = Result<Box<[u8]>, Box<dyn Error>>> + '_
    where
        TKey: Clone + AsRef<[u8]>,
        TData: DeserializeOwned,
    {
        let db_key = {
            let mut db_key = DbKey::prefix_only(&self.prefix);
            db_key.add_bucket(&key);
            db_key
        };

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_range(rocksdb::PrefixRange(db_key.as_ref()));

        let mut db_iterator = self.db.iterator_opt(IteratorMode::Start, read_opts);

        if skip_first {
            db_iterator.next();
        }

        db_iterator.take(limit).map(move |item| match item {
            Ok((key_bytes, _)) => Ok(key_bytes[db_key.prefix_len()..].into()),
            Err(err) => Err(err.into()),
        })
    }

    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    fn bucket_iterator(&self, key: TKey) -> impl Iterator<Item = Result<TData, Box<dyn Error>>> + '_
    where
        TKey: Clone + AsRef<[u8]>,
        TData: DeserializeOwned,
    {
        self.seek_iterator(key, usize::MAX, false).map(|res| {
            let data = res.unwrap();
            Ok(bincode::deserialize(&data)?)
        })
    }
}
