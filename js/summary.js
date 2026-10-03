import { STRIDE, PRIORITIES } from './stencils.js';
import { STATUSES, STATUS_LABELS } from './threats.js';
import { threatStats } from './engine.js';

// All model threats, independently of the current list filters or diagram.
export function renderThreatSummary(threats) {
  const stats = threatStats(threats);
  return `<p class="muted">All diagrams · ${stats.total} threats · ${stats.orphaned} orphaned. Includes custom threats; list filters do not affect these counts.</p>
    <div class="status-cards">${STATUSES.map((status) => `<div class="status-card"><span class="state" data-s="${STATUS_LABELS[status]}">${STATUS_LABELS[status]}</span><strong>${stats.byStatus[status]}</strong></div>`).join('')}</div>
    <div class="summary-table-wrap"><table class="summary-table">
      <caption>Threats by STRIDE category and status</caption>
      <thead><tr><th scope="col">Category</th>${STATUSES.map((s) => `<th scope="col">${STATUS_LABELS[s]}</th>`).join('')}<th scope="col">Total</th></tr></thead>
      <tbody>${STRIDE.map((c) => `<tr><th scope="row"><span class="cat" style="background:${c.color}">${c.key}</span> ${c.name}</th>${STATUSES.map((s) => `<td>${stats.byCatStatus[c.key][s]}</td>`).join('')}<td>${stats.byCat[c.key]}</td></tr>`).join('')}</tbody>
      <tfoot><tr><th scope="row">Total</th>${STATUSES.map((s) => `<td>${stats.byStatus[s]}</td>`).join('')}<td>${stats.total}</td></tr></tfoot>
    </table></div>
    <p class="summary-severity">${PRIORITIES.map((s) => `<span>${s} severity: <b>${stats.bySeverity[s]}</b></span>`).join('')}</p>
    ${stats.total ? '' : '<p class="muted">Connect elements in a diagram to generate threats, or add a custom threat in Analysis.</p>'}`;
}
