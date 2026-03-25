/**
 * PhishGuard – IndexedDB Cache Layer
 *
 * A minimal, promise-based wrapper around IndexedDB.
 * All four caches that previously lived in in-memory Maps now persist here
 * across service-worker restarts:
 *
 *   Store name        Key             Value shape
 *   ─────────────────────────────────────────────────────────────────
 *   'rdap'            registeredDomain  { result, cachedAt }
 *   'safebrowsing'    url               { flagged, cachedAt }
 *   'phishtank'       url               { flagged, cachedAt }
 *   'notifications'   domain            { lastNotifiedAt }
 */

const DB_NAME    = 'phishguard-cache';
const DB_VERSION = 1;
const STORES     = ['rdap', 'safebrowsing', 'phishtank', 'notifications'];

/** Singleton DB connection promise — opened once, reused forever. */
let _dbPromise = null;

function openDB() {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      for (const name of STORES) {
        if (!db.objectStoreNames.contains(name)) {
          db.createObjectStore(name);
        }
      }
    };

    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => {
      _dbPromise = null;  // allow retry on next call
      reject(e.target.error);
    };
    req.onblocked = () => {
      console.warn('[PhishGuard IDB] upgrade blocked — another tab has the DB open');
    };
  });
  return _dbPromise;
}

/**
 * Read one entry.
 * @returns {Promise<any|null>}  The stored value, or null if not found.
 */
export async function idbGet(storeName, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(storeName, 'readonly')
                  .objectStore(storeName)
                  .get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

/**
 * Write one entry (upsert).
 * @returns {Promise<void>}
 */
export async function idbSet(storeName, key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(storeName, 'readwrite')
                  .objectStore(storeName)
                  .put(value, key);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}

/**
 * Delete one entry.
 * @returns {Promise<void>}
 */
export async function idbDelete(storeName, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(storeName, 'readwrite')
                  .objectStore(storeName)
                  .delete(key);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}

/**
 * Prune all entries in a store whose `cachedAt` field is older than ttlMs.
 * Runs in a single read-write cursor transaction — O(n) but called infrequently.
 * @param {string}  storeName  One of the store names above.
 * @param {number}  ttlMs      Maximum age in milliseconds.
 * @returns {Promise<number>}  Count of deleted entries.
 */
export async function idbPrune(storeName, ttlMs) {
  const db      = await openDB();
  const cutoff  = Date.now() - ttlMs;
  let   deleted = 0;

  return new Promise((resolve, reject) => {
    const tx    = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const req   = store.openCursor();

    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (!cursor) return resolve(deleted);
      const { cachedAt, lastNotifiedAt } = cursor.value;
      const age = cachedAt ?? lastNotifiedAt ?? Infinity;
      if (age < cutoff) { cursor.delete(); deleted++; }
      cursor.continue();
    };
    req.onerror = () => reject(req.error);
  });
}
