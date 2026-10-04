// Review fields and backwards-compatible reads for saved threat records.
import { PRIORITIES, STRIDE_BY_KEY } from './stencils.js';

export const STATUSES = ['open', 'mitigated', 'accepted', 'not-applicable'];
export const STATUS_LABELS = { open: 'Open', mitigated: 'Mitigated', accepted: 'Accepted', 'not-applicable': 'Not Applicable' };
const LEGACY_STATUS = { 'Not Started': 'open', 'Needs Investigation': 'open', Open: 'open', Mitigated: 'mitigated', Accepted: 'accepted', 'Not Applicable': 'not-applicable' };
const LEGACY_STATE = { open: 'Not Started', mitigated: 'Mitigated', accepted: 'Accepted', 'not-applicable': 'Not Applicable' };

export const threatStatus = (t) => STATUSES.includes(t.status) ? t.status : Object.hasOwn(LEGACY_STATUS, t.state) ? LEGACY_STATUS[t.state] : 'open';
export const effectiveThreatStatus = (t) => t.needsReview ? 'open' : threatStatus(t);
export const threatSeverity = (t) => PRIORITIES.includes(t.severity) ? t.severity : PRIORITIES.includes(t.priority) ? t.priority : 'Medium';
export const contributingFlowText = (t) => (t.contributingFlows || []).map((f) => `${f.interaction} [${f.id}]`).join('\n');
export const newFlowsSinceReview = (t) => (t.contributingFlows || []).filter((f) => !(t.reviewedFlowIds || []).includes(f.id));
export function reviewNotice(t) {
  if (!t.needsReview) return '';
  const flows = newFlowsSinceReview(t);
  return flows.length ? `New flows since review: ${flows.map((f) => f.name || f.interaction || f.id).join(', ')}`
    : 'Review required: confirm the status for all contributing flows.';
}

export function validateReview(t) {
  if (t.status != null && !STATUSES.includes(t.status)) throw new Error('Invalid threat status.');
  if (t.severity != null && !PRIORITIES.includes(t.severity)) throw new Error('Invalid threat severity.');
  for (const field of ['notes', 'owner', 'mitigation', 'justification']) {
    if (t[field] != null && typeof t[field] !== 'string') throw new Error(`Invalid threat ${field}.`);
  }
  if (t.contributingFlows != null && (!Array.isArray(t.contributingFlows) || t.contributingFlows.some((f) =>
    !f || typeof f !== 'object' || ['id', 'sourceId', 'targetId', 'name', 'interaction'].some((key) => typeof f[key] !== 'string')))) {
    throw new Error('Invalid threat contributing flows.');
  }
  if (t.suppressed != null && typeof t.suppressed !== 'boolean') throw new Error('Invalid threat suppression flag.');
  if (t.needsReview != null && typeof t.needsReview !== 'boolean') throw new Error('Invalid threat review flag.');
  if (t.reviewedFlowIds != null && (!Array.isArray(t.reviewedFlowIds) || t.reviewedFlowIds.some((id) => typeof id !== 'string'))) {
    throw new Error('Invalid threat reviewed flow IDs.');
  }
}

export function updateThreat(t, field, value) {
  if (!['status', 'severity', 'notes', 'owner', 'mitigation', 'justification', 'title', 'description', 'category'].includes(field)) {
    throw new Error('Unknown threat field.');
  }
  if (typeof value !== 'string') throw new Error('Threat fields must be text.');
  validateReview({ ...t, [field]: value });
  if (field === 'category' && !Object.hasOwn(STRIDE_BY_KEY, value)) throw new Error('Invalid STRIDE category.');
  if (field === 'status') {
    // Preserve the imported state before mirroring subsequent user decisions.
    if (t.status == null && t.state) t.legacyState ??= t.state;
    t.state = LEGACY_STATE[value];
    if (t.dedupeKey && t.contributingFlows) {
      if (value !== 'open') t.reviewedFlowIds = t.contributingFlows.map((f) => f.id);
      else delete t.reviewedFlowIds;
      t.needsReview = false;
    }
  }
  t[field] = value;
  if (field === 'title' || field === 'description') t.customText = true;
  t.modified = new Date().toISOString();
}

export function matchesThreat(t, { text = '', status = '', severity = '', category = '' } = {}) {
  if (status && effectiveThreatStatus(t) !== status) return false;
  if (severity && threatSeverity(t) !== severity) return false;
  if (category && t.category !== category) return false;
  const query = text.trim().toLowerCase();
  return !query || [t.id, t.title, t.description, t.interaction, contributingFlowText(t), t.justification, t.notes, t.owner, t.mitigation]
    .join(' ').toLowerCase().includes(query.replace(/^#(?=\d)/, ''));
}
