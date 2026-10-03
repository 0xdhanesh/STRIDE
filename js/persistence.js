// Local-only recovery. IndexedDB is the durable store; localStorage bridges
// the short interval between an edit and the IndexedDB transaction completing.
const DB_NAME = 'stride-tm';
const JOURNAL = 'stride-tm:recovery:v1';
const LEGACY = 'stride-tm:model:v1';

export class LocalAutosave {
  constructor({ indexedDB = globalThis.indexedDB, storage, onStatus = () => {} } = {}) {
    this.indexedDB = indexedDB;
    try { this.storage = storage === undefined ? globalThis.localStorage : storage; } catch {}
    this.onStatus = onStatus;
    this.sequence = 0;
    this.pending = Promise.resolve();
  }

  read(key) {
    try { return JSON.parse(this.storage?.getItem(key) || 'null'); } catch { return null; }
  }

  async open() {
    if (this.connection) return this.connection;
    this.connection = new Promise((resolve, reject) => {
      if (!this.indexedDB) return reject(new Error('IndexedDB is unavailable.'));
      const request = this.indexedDB.open(DB_NAME, 1);
      let expired = false;
      const timer = setTimeout(() => {
        expired = true;
        reject(new Error('Browser storage did not respond.'));
      }, 3000);
      request.onupgradeneeded = () => request.result.createObjectStore('models');
      request.onerror = () => { clearTimeout(timer); reject(request.error); };
      request.onblocked = () => { clearTimeout(timer); expired = true; reject(new Error('Browser storage is blocked by another tab.')); };
      request.onsuccess = () => {
        clearTimeout(timer);
        const db = request.result;
        if (expired) { db.close(); return; }
        db.onversionchange = () => { db.close(); this.connection = null; };
        resolve(db);
      };
    }).catch((error) => { this.connection = null; throw error; });
    return this.connection;
  }

  async transact(mode, record) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('models', mode);
      const store = tx.objectStore('models');
      const request = mode === 'readonly' ? store.get('current') : store.put(record, 'current');
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = tx.onerror = () => reject(tx.error || request.error || new Error('Autosave transaction failed.'));
    });
  }

  async restore() {
    let saved;
    try { saved = await this.transact('readonly'); }
    catch { this.onStatus('fallback'); }
    const journal = this.read(JOURNAL);
    const candidates = [saved, journal].filter((r) => r && typeof r.snapshot === 'string' && Number.isFinite(r.savedAt));
    candidates.sort((a, b) => b.savedAt - a.savedAt);
    this.sequence = candidates[0]?.savedAt || 0;
    const legacy = this.read(LEGACY);
    if (legacy) candidates.push({ snapshot: JSON.stringify(legacy), savedAt: 0 });
    return candidates;
  }

  save(snapshot) {
    if (snapshot === this.lastSnapshot && ['saving', 'saved'].includes(this.status)) return this.pending;
    this.lastSnapshot = snapshot;
    const record = { snapshot, savedAt: Math.max(Date.now(), this.sequence + 1) };
    this.sequence = record.savedAt;
    let journaled = false;
    try { this.storage.setItem(JOURNAL, JSON.stringify(record)); journaled = true; } catch {}
    this.journaled = journaled;
    this.status = 'saving';
    this.onStatus(this.status);
    // Queue writes in edit order. A failed write must not block later saves.
    this.pending = this.pending.then(async () => {
      try {
        await this.transact('readwrite', record);
        if (this.read(JOURNAL)?.savedAt === record.savedAt) {
          try { this.storage.removeItem(JOURNAL); } catch {}
        }
        try { this.storage?.removeItem(LEGACY); } catch {}
        if (record.savedAt === this.sequence) { this.status = 'saved'; this.onStatus(this.status); }
        return true;
      } catch {
        if (record.savedAt === this.sequence) { this.status = journaled ? 'fallback' : 'error'; this.onStatus(this.status); }
        return false;
      }
    });
    return this.pending;
  }
}
