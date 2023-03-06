mod stores;

extern crate self as address_manager;

use std::{collections::HashSet, net::IpAddr, sync::Arc};

use database::prelude::{StoreResultExtensions, DB};
use kaspa_core::time::unix_now;
use parking_lot::Mutex;

use stores::banned_address_store::{BannedAddressesStore, BannedAddressesStoreReader, ConnectionBanTimestamp, DbBannedAddressesStore};

pub use stores::NetAddress;

const MAX_ADDRESSES: usize = 4096;
const MAX_CONNECTION_FAILED_COUNT: u64 = 3;

pub struct AddressManager {
    banned_address_store: DbBannedAddressesStore,
    not_banned_address_store: not_banned_address_store_with_cache::Store,
}

impl AddressManager {
    pub fn new(db: Arc<DB>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            banned_address_store: DbBannedAddressesStore::new(db.clone(), MAX_ADDRESSES as u64),
            not_banned_address_store: not_banned_address_store_with_cache::new(db),
        }))
    }

    pub fn add_address(&mut self, address: NetAddress) {
        // TODO: Don't add non routable addresses

        if self.not_banned_address_store.has(address) {
            return;
        }

        // We mark `connection_failed_count` as 0 only after first success
        self.not_banned_address_store.set(address, 1);
    }

    pub fn mark_connection_failure(&mut self, address: NetAddress) {
        if !self.not_banned_address_store.has(address) {
            return;
        }

        let new_count = self.not_banned_address_store.get(address).connection_failed_count + 1;
        if new_count > MAX_CONNECTION_FAILED_COUNT {
            self.not_banned_address_store.remove(address);
        } else {
            self.not_banned_address_store.set(address, new_count);
        }
    }

    pub fn mark_connection_success(&mut self, address: NetAddress) {
        if !self.not_banned_address_store.has(address) {
            return;
        }

        self.not_banned_address_store.set(address, 0);
    }

    pub fn get_all_addresses(&self) -> impl Iterator<Item = NetAddress> + '_ {
        self.not_banned_address_store.get_all_addresses()
    }

    pub fn get_random_addresses(&self, exceptions: HashSet<NetAddress>) -> Vec<NetAddress> {
        self.not_banned_address_store.get_randomized_addresses(exceptions)
    }

    pub fn ban(&mut self, ip: IpAddr) {
        self.banned_address_store.set(ip, ConnectionBanTimestamp(unix_now())).unwrap();
        self.not_banned_address_store.remove_by_ip(ip);
    }

    pub fn unban(&mut self, ip: IpAddr) {
        self.banned_address_store.remove(ip).unwrap();
    }

    pub fn is_banned(&mut self, ip: IpAddr) -> bool {
        const MAX_BANNED_TIME: u64 = 24 * 60 * 60 * 1000;
        match self.banned_address_store.get(ip).unwrap_option() {
            Some(timestamp) => {
                if unix_now() - timestamp.0 > MAX_BANNED_TIME {
                    self.unban(ip);
                    false
                } else {
                    true
                }
            }
            None => false,
        }
    }
}

mod not_banned_address_store_with_cache {
    // Since we need operations such as iterating all addresses, count, etc, we keep an easy to use copy of the database addresses.
    // We don't expect it to be expensive since we limit the number of saved addresses.
    use std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        sync::Arc,
    };

    use database::prelude::DB;
    use itertools::Itertools;
    use rand::{distributions::WeightedIndex, prelude::Distribution};

    use crate::{
        stores::{
            not_banned_address_store::{DbNotBannedAddressesStore, Entry, NotBannedAddressesStore},
            AddressKey,
        },
        NetAddress, MAX_ADDRESSES, MAX_CONNECTION_FAILED_COUNT,
    };

    pub struct Store {
        db_store: DbNotBannedAddressesStore,
        addresses: HashMap<AddressKey, Entry>,
    }

    impl Store {
        fn new(db: Arc<DB>) -> Self {
            let db_store = DbNotBannedAddressesStore::new(db, 0);
            let mut addresses = HashMap::new();
            for (key, entry) in db_store.iterator().map(|res| res.unwrap()) {
                addresses.insert(key, entry);
            }

            Self { db_store, addresses }
        }

        pub fn has(&mut self, address: NetAddress) -> bool {
            self.addresses.contains_key(&address.into())
        }

        pub fn set(&mut self, address: NetAddress, connection_failed_count: u64) {
            let entry = match self.addresses.get(&address.into()) {
                Some(entry) => Entry { connection_failed_count, address: entry.address },
                None => Entry { connection_failed_count, address },
            };
            self.db_store.set(address.into(), entry).unwrap();
            self.addresses.insert(address.into(), entry);
            self.keep_limit();
        }

        fn keep_limit(&mut self) {
            while self.addresses.len() > MAX_ADDRESSES {
                let to_remove =
                    self.addresses.iter().max_by(|a, b| (a.1).connection_failed_count.cmp(&(b.1).connection_failed_count)).unwrap();
                self.remove_by_key(*to_remove.0);
            }
        }

        pub fn get(&self, address: NetAddress) -> Entry {
            *self.addresses.get(&address.into()).unwrap()
        }

        pub fn remove(&mut self, address: NetAddress) {
            self.remove_by_key(address.into())
        }

        fn remove_by_key(&mut self, key: AddressKey) {
            self.addresses.remove(&key);
            self.db_store.remove(key).unwrap()
        }

        pub fn get_all_addresses(&self) -> impl Iterator<Item = NetAddress> + '_ {
            self.addresses.values().map(|entry| entry.address)
        }

        pub fn get_randomized_addresses(&self, exceptions: HashSet<NetAddress>) -> Vec<NetAddress> {
            let exceptions: HashSet<AddressKey> = exceptions.into_iter().map(|addr| addr.into()).collect();
            let addresses = self.addresses.iter().filter(|(addr, _)| !exceptions.contains(addr)).collect_vec();
            let mut weights = addresses
                .iter()
                .map(|(_, entry)| 64f64.powf((MAX_CONNECTION_FAILED_COUNT + 1 - entry.connection_failed_count) as f64))
                .collect_vec();

            (0..addresses.len())
                .map(|_| {
                    let dist = WeightedIndex::new(&weights).unwrap();
                    let i = dist.sample(&mut rand::thread_rng());
                    weights[i] = 0f64;
                    addresses[i].1.address
                })
                .collect_vec()
        }

        pub fn remove_by_ip(&mut self, ip: IpAddr) {
            for key in self.addresses.keys().filter(|key| key.is_ip(ip)).copied().collect_vec() {
                self.remove_by_key(key);
            }
        }
    }

    pub fn new(db: Arc<DB>) -> Store {
        Store::new(db)
    }
}
