//! The keys that `Signatures::sign_held` imported into SymCrypt, kept while
//! the object holding them lives, so that a key is imported (and checked)
//! once rather than for every signature.
//!
//! # Which key an entry signs for
//!
//! An entry is found by the address of the holder's `Arc` allocation and
//! the key's slot in it, and keeps a `Weak` to the holder. The `Weak` keeps
//! the allocation, so no other holder can take that address while the entry
//! exists, and nothing can change the keys the holder shares meanwhile (see
//! [`KeyHolder`]). An entry therefore only ever signs for the private key it
//! was imported from. A key with the same public key but another private
//! part is held elsewhere, and is imported on its own: the import fails
//! unless its private part matches its public one.
//!
//! # Lifetime
//!
//! The cache holds at most `capacity` keys and evicts the least recently
//! used one to make room. An entry whose holder was dropped is removed at
//! the next lookup, or by `remove_dropped`, which russh calls when it drops
//! keys. A removed key is dropped once the signatures in progress with it
//! are done, which frees it with `SymCryptEckeyFree` or
//! `SymCryptRsakeyFree`: these wipe it.
//!
//! # Threads
//!
//! The entries are behind a mutex, which is only held to find, add and
//! remove entries: keys are imported, used and dropped without it. SymCrypt
//! signs through a pointer to a `const` key, which several threads may use
//! at once (the `MULTI_THREADING` section of `symcrypt.h`). The mutex also
//! orders the import of a key before its use by other threads.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use crate::crypto::KeyHolder;

/// Values made from keys of [`KeyHolder`]s.
pub(super) struct KeyCache<V> {
    capacity: usize,
    /// From the least to the most recently used.
    entries: Mutex<Vec<Entry<V>>>,
}

struct Entry<V> {
    holder: Weak<dyn KeyHolder>,
    slot: usize,
    value: Arc<V>,
}

impl<V> Entry<V> {
    fn is_for(&self, holder: *const (), slot: usize) -> bool {
        self.slot == slot && std::ptr::addr_eq(self.holder.as_ptr(), holder)
    }
}

impl<V> KeyCache<V> {
    /// A cache of at most `capacity` values, which must be at least 1.
    pub(super) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Vec::new()),
        }
    }

    /// The value for key `slot` of `holder`: the cached one, or else the
    /// one `make` returns, which is cached unless it is an error.
    pub(super) fn get_or_try_insert_with<H: KeyHolder, E>(
        &self,
        holder: &Arc<H>,
        slot: usize,
        make: impl FnOnce() -> Result<V, E>,
    ) -> Result<Arc<V>, E> {
        let address = Arc::as_ptr(holder).cast::<()>();
        // Declared first, to be dropped after the lock is released.
        let mut removed = Vec::new();
        if let Some(value) = touch(&mut self.lock(&mut removed), address, slot) {
            return Ok(value);
        }
        // Made without the lock, so that other keys can be used meanwhile.
        let value = Arc::new(make()?);
        let mut entries = self.lock(&mut removed);
        if let Some(cached) = touch(&mut entries, address, slot) {
            // Another thread made it meanwhile: `value` is dropped.
            return Ok(cached);
        }
        if entries.len() >= self.capacity && !entries.is_empty() {
            removed.push(entries.remove(0));
        }
        let weak = Arc::downgrade(holder);
        entries.push(Entry {
            holder: weak,
            slot,
            value: Arc::clone(&value),
        });
        Ok(value)
    }

    /// Removes the entries whose holder was dropped.
    pub(super) fn remove_dropped(&self) {
        let mut removed = Vec::new();
        drop(self.lock(&mut removed));
    }

    /// Locks the entries, after moving those whose holder was dropped to
    /// `removed`.
    fn lock(&self, removed: &mut Vec<Entry<V>>) -> MutexGuard<'_, Vec<Entry<V>>> {
        // The entries are consistent even if a thread panicked with the
        // lock: nothing in this module panics while holding it.
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut index = 0;
        while let Some(entry) = entries.get(index) {
            if entry.holder.strong_count() == 0 {
                removed.push(entries.remove(index));
            } else {
                index += 1;
            }
        }
        entries
    }

    /// The number of entries whose holder lives.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        let mut removed = Vec::new();
        self.lock(&mut removed).len()
    }
}

/// The value of the entry for key `slot` of the holder at `address`, which
/// becomes the most recently used.
fn touch<V>(entries: &mut Vec<Entry<V>>, address: *const (), slot: usize) -> Option<Arc<V>> {
    let index = entries
        .iter()
        .position(|entry| entry.is_for(address, slot))?;
    let entry = entries.remove(index);
    let value = Arc::clone(&entry.value);
    entries.push(entry);
    Some(value)
}
