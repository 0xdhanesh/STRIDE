import test from 'node:test';
import assert from 'node:assert/strict';
import { LocalAutosave } from '../js/persistence.js';
import { Store, normalizeModel, newModel, newDiagram } from '../js/store.js';
import { sampleModel } from '../js/sample.js';
import { syncThreats } from '../js/engine.js';
import { DEFAULT_RULES } from '../js/rules.js';
import { readModelFile, serializeModel, saveModelFile } from '../js/io.js';
import { updateThreat } from '../js/threats.js';

const JOURNAL = 'stride-tm:recovery:v1';
const LEGACY = 'stride-tm:model:v1';
class MemoryStorage {
  data = new Map();
  getItem(key) { return this.data.get(key) ?? null; }
  setItem(key, value) { if (this.fail) throw new Error('QuotaExceededError'); this.data.set(key, value); }
  removeItem(key) { this.data.delete(key); }
}
// Only the database boundary is substituted. Real serialization, journaling,
// recovery selection, write ordering, store commits and undo/redo run unchanged.
class TestAutosave extends LocalAutosave {
  constructor(storage = new MemoryStorage(), disk = {}) {
    super({ storage }); this.disk = disk;
  }
  async transact(mode, record) {
    if (this.fail) throw new Error('Storage blocked');
    if (mode === 'readonly') return structuredClone(this.disk.record);
    if (this.gate) await this.gate;
    this.disk.record = structuredClone(record);
  }
}
function reviewedModel() {
  const m = normalizeModel(sampleModel());
  m.meta.title = 'Banking — نموذج';
  m.meta.owner = 'Security review';
  m.diagrams.push(newDiagram('Second diagram'));
  m.template = structuredClone(DEFAULT_RULES);
  syncThreats(m);
  for (const t of Object.values(m.threats)) {
    updateThreat(t, 'status', 'mitigated'); t.justification = 'Control tested\nEvidence retained';
    t.mitigation = 'Mutual TLS and least privilege'; t.modified = '2026-10-03T10:00:00.000Z';
    t.notes = 'Additional audit notes'; t.owner = 'Alice'; t.severity = 'High';
  }
  const custom = structuredClone(Object.values(m.threats)[0]);
  Object.assign(custom, { id: m.nextThreatId++, key: 'custom:review', auto: false, customText: true, orphan: true, title: 'Retained custom finding' });
  m.threats[custom.key] = custom;
  return m;
}
const file = (model, name = 'bank.stride') => ({ name, text: async () => serializeModel(model) });

test('full .stride and legacy JSON files round-trip without changing decisions or regenerating threats', async () => {
  const m = reviewedModel();
  for (const name of ['bank.stride', 'bank.stride.json', 'bank.json']) {
    const reopened = await readModelFile(file(m, name));
    assert.deepEqual(reopened, m);
    const store = new Store({ autosave: new TestAutosave() });
    store.replaceModel(reopened);
    assert.deepEqual(store.model, m);
    await store.autosave.pending;
  }
});

test('file download uses .stride and contains the entire model', () => {
  const m = reviewedModel();
  const originalDocument = globalThis.document;
  const originalCreate = URL.createObjectURL;
  const originalTimer = globalThis.setTimeout;
  let blob, clicked = false;
  const link = { click() { clicked = true; }, remove() {} };
  try {
    globalThis.document = { createElement: () => link, body: { appendChild() {} } };
    URL.createObjectURL = (value) => { blob = value; return 'blob:local'; };
    globalThis.setTimeout = () => 0;
    saveModelFile(m);
    assert.equal(clicked, true);
    assert.match(link.download, /\.stride$/);
    assert.equal(blob.type, 'application/json');
    return blob.text().then((text) => assert.deepEqual(JSON.parse(text), m));
  } finally {
    globalThis.document = originalDocument; URL.createObjectURL = originalCreate; globalThis.setTimeout = originalTimer;
  }
});

test('invalid or unsupported files do not replace model, selection, or history', async () => {
  const store = new Store({ autosave: new TestAutosave() });
  store.replaceModel(reviewedModel());
  const before = structuredClone(store.model), past = [...store.past];
  for (const mutate of [
    (m) => { m.version = 99; },
    (m) => { m.diagrams[0].elements[0].type = 'unknown'; },
    (m) => { m.diagrams[1].id = m.diagrams[0].id; },
    (m) => { m.diagrams[0].elements[0].x = 'NaN'; },
    (m) => { m.diagrams[0].elements[0].style.stroke = 'url(https://example.com)'; },
    (m) => { m.threats.bad = null; },
    (m) => { m.template = [{}]; },
  ]) {
    const invalid = structuredClone(before); mutate(invalid);
    assert.throws(() => store.replaceModel(invalid));
    assert.deepEqual(store.model, before); assert.deepEqual(store.past, past);
  }
  await assert.rejects(readModelFile({ name: 'bad.stride', text: async () => '{' }), /valid JSON/);
  await store.autosave.pending;
});

test('IndexedDB recovery preserves edited threats, diagrams and template exactly', async () => {
  const autosave = new TestAutosave();
  const original = new Store({ autosave });
  original.replaceModel(reviewedModel());
  await autosave.pending;
  assert.equal(autosave.storage.getItem(JOURNAL), null);
  const recovered = new Store({ autosave: new TestAutosave(autosave.storage, autosave.disk) });
  await recovered.restore();
  assert.deepEqual(recovered.model, original.model);
  await recovered.autosave.pending;
});

test('refresh before a database write completes recovers the newest synchronous journal', async () => {
  const autosave = new TestAutosave();
  let release;
  autosave.gate = new Promise((resolve) => { release = resolve; });
  const model = reviewedModel();
  autosave.save(JSON.stringify(newModel()));
  autosave.save(JSON.stringify(model));
  assert.deepEqual(JSON.parse(JSON.parse(autosave.storage.getItem(JOURNAL)).snapshot), model);
  const restored = new Store({ autosave: new TestAutosave(autosave.storage, autosave.disk) });
  await restored.restore();
  assert.deepEqual(restored.model, model);
  release();
  await Promise.all([autosave.pending, restored.autosave.pending]);
});

test('legacy localStorage is migrated only after a successful database commit', async () => {
  const autosave = new TestAutosave();
  const model = reviewedModel();
  autosave.storage.setItem(LEGACY, JSON.stringify(model));
  autosave.fail = true;
  const store = new Store({ autosave });
  await store.restore(); await autosave.pending;
  assert.deepEqual(store.model, model);
  assert.notEqual(autosave.storage.getItem(LEGACY), null);
  assert.equal(store.saveStatus, 'fallback');
  autosave.fail = false;
  await store.persist();
  assert.equal(autosave.storage.getItem(LEGACY), null);
  assert.equal(store.saveStatus, 'saved');
});

test('failed storage is visible and later saves recover; stale journal cannot supersede newer database', async () => {
  const autosave = new TestAutosave();
  autosave.fail = true; autosave.storage.fail = true;
  const store = new Store({ autosave });
  store.replaceModel(reviewedModel());
  await autosave.pending;
  assert.equal(store.saveStatus, 'error');
  autosave.fail = false; autosave.storage.fail = false;
  await store.persist();
  assert.equal(store.saveStatus, 'saved');
  autosave.storage.setItem(JOURNAL, JSON.stringify({ snapshot: JSON.stringify(newModel()), savedAt: 1 }));
  const recovered = new Store({ autosave: new TestAutosave(autosave.storage, autosave.disk) });
  await recovered.restore();
  assert.deepEqual(recovered.model, store.model);
  await recovered.autosave.pending;
});

test('corrupt recovery does not silently overwrite saved bytes', async () => {
  const autosave = new TestAutosave();
  autosave.disk.record = { snapshot: '{corrupt', savedAt: 1 };
  const store = new Store({ autosave });
  await store.restore();
  assert.equal(store.saveStatus, 'recovery-error');
  assert.equal(autosave.disk.record.snapshot, '{corrupt');
});

test('commit, undo, redo and unblurred threat notes each autosave their current contents', async () => {
  const autosave = new TestAutosave();
  const store = new Store({ autosave });
  store.replaceModel(reviewedModel());
  store.model.meta.title = 'Changed'; store.commit();
  store.undo(); await autosave.pending;
  assert.equal(JSON.parse(autosave.disk.record.snapshot).meta.title, 'Banking — نموذج');
  store.redo(); await autosave.pending;
  assert.equal(JSON.parse(autosave.disk.record.snapshot).meta.title, 'Changed');
  Object.values(store.model.threats)[0].justification = 'Still typing';
  await store.persist();
  assert.equal(Object.values(JSON.parse(autosave.disk.record.snapshot).threats)[0].justification, 'Still typing');
});

test('IndexedDB adapter waits for transaction completion, and rejects transaction abort', async () => {
  const autosave = new LocalAutosave({ storage: new MemoryStorage() });
  let tx;
  autosave.open = async () => ({ transaction(name, mode) {
    assert.equal(name, 'models'); assert.equal(mode, 'readwrite');
    tx = { objectStore: () => ({ put: () => ({ result: 'current' }) }) }; return tx;
  } });
  let finished = false;
  const pending = autosave.transact('readwrite', {}).then(() => { finished = true; });
  await Promise.resolve(); assert.equal(finished, false);
  tx.oncomplete(); await pending; assert.equal(finished, true);
  const failed = autosave.transact('readwrite', {});
  await Promise.resolve(); tx.error = new Error('Quota exceeded'); tx.onabort();
  await assert.rejects(failed, /Quota exceeded/);
});
