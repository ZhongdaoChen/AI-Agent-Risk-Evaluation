(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ReportExporter = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  const DEFAULT_PHASE_ORDER = ['code', 'skill', 'ai_safety', 'github', 'depsdev', 'deps', 'privacy', 'supply_chain', 'runtime'];

  function text(value) {
    return value === null || value === undefined ? '' : String(value);
  }

  function escapeHtml(value) {
    return text(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function stripHtml(value) {
    return text(value)
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
      .replace(/<[^>]*>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/[ \t]+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  function plain(value) {
    return stripHtml(value).replace(/\s+\n/g, '\n').trim();
  }

  function markdownCell(value) {
    return plain(value).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
  }

  function reportFileStem(target) {
    const safeTarget = text(target || 'unknown-repository')
      .trim()
      .replace(/\s+/g, '-')
      .replace(/[\\/]+/g, '_')
      .replace(/[^\w.-]+/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_+|_+$/g, '');
    return `ai-risk-report-${safeTarget || 'unknown-repository'}`;
  }

  function orderedEntries(results, phaseOrder) {
    const keys = Object.keys(results || {});
    const order = phaseOrder && phaseOrder.length ? phaseOrder : DEFAULT_PHASE_ORDER;
    const ordered = order.filter(key => Object.prototype.hasOwnProperty.call(results || {}, key));
    keys.forEach(key => {
      if (!ordered.includes(key)) ordered.push(key);
    });
    return ordered.map(key => [key, results[key]]);
  }

  function phaseLabel(key, phaseMeta) {
    const meta = (phaseMeta || {})[key] || {};
    return `${meta.icon ? `${meta.icon} ` : ''}${meta.label || key}`;
  }

  function normalizeFinding(finding) {
    const title = finding && finding.is_html ? plain(finding.title) : plain(finding && finding.title);
    const detail = finding && finding.is_html ? plain(finding.detail) : plain(finding && finding.detail);
    return {
      type: text(finding && finding.type) || 'INFO',
      title: title || '(untitled finding)',
      detail,
    };
  }

  function buildMarkdownReport(state) {
    const target = text(state && state.target) || 'Unknown repository';
    const generatedAt = text(state && state.generatedAt) || new Date().toISOString();
    const overall = (state && state.overall) || {};
    const results = (state && state.results) || {};
    const controls = Array.isArray(state && state.controls) ? state.controls : [];
    const lines = [];

    lines.push('# AI Agent Risk Assessment Report');
    lines.push('');
    lines.push(`**Repository:** ${target}`);
    lines.push(`**Generated:** ${generatedAt}`);
    lines.push('');
    lines.push('## Overall Risk');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|---|---|');
    lines.push(`| Overall Score | ${markdownCell(overall.score)} / 100 |`);
    lines.push(`| Risk Level | ${markdownCell(overall.risk_level)} |`);
    if (overall.label) lines.push(`| Label | ${markdownCell(overall.label)} |`);
    if (Array.isArray(overall.excluded_modules) && overall.excluded_modules.length) {
      lines.push(`| Excluded Modules | ${markdownCell(overall.excluded_modules.join(', '))} |`);
    }
    lines.push('');
    lines.push('## Module Results');

    orderedEntries(results, state && state.phaseOrder).forEach(([key, result]) => {
      const findings = Array.isArray(result && result.findings) ? result.findings : [];
      lines.push('');
      lines.push(`### ${phaseLabel(key, state && state.phaseMeta)}`);
      lines.push('');
      lines.push('| Metric | Value |');
      lines.push('|---|---|');
      lines.push(`| Score | ${markdownCell(result && result.score)} / 100 |`);
      lines.push(`| Risk Level | ${markdownCell(result && result.risk_level)} |`);
      lines.push(`| Summary | ${markdownCell(result && result.summary)} |`);
      lines.push('');
      if (!findings.length) {
        lines.push('No findings.');
        return;
      }
      findings.forEach(rawFinding => {
        const finding = normalizeFinding(rawFinding);
        lines.push(`#### ${finding.type}: ${finding.title}`);
        if (finding.detail) {
          lines.push('');
          lines.push(finding.detail);
        }
        lines.push('');
      });
    });

    if (controls.length) {
      lines.push('');
      lines.push('## AppSec Security Controls');
      controls.forEach(control => {
        const priority = text(control.priority || 'RECOMMEND');
        lines.push('');
        lines.push(`### ${priority}: ${plain(control.title) || '(untitled control)'}`);
        if (control.category) lines.push(`**Category:** ${plain(control.category)}`);
        if (control.precondition) lines.push(`**Precondition:** ${plain(control.precondition)}`);
        if (control.reason) lines.push(`**Reason:** ${plain(control.reason)}`);
        if (control.implementation) lines.push(`**Implementation:** ${plain(control.implementation)}`);
        if (control.example) {
          lines.push('');
          lines.push('```');
          lines.push(text(control.example).trim());
          lines.push('```');
        }
      });
    }

    return `${lines.join('\n').replace(/\n{4,}/g, '\n\n\n').trim()}\n`;
  }

  function riskClass(risk) {
    return {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
      UNKNOWN: 'unknown',
    }[text(risk).toUpperCase()] || 'unknown';
  }

  function buildHtmlReport(state) {
    const target = text(state && state.target) || 'Unknown repository';
    const generatedAt = text(state && state.generatedAt) || new Date().toISOString();
    const overall = (state && state.overall) || {};
    const results = (state && state.results) || {};
    const controls = Array.isArray(state && state.controls) ? state.controls : [];
    const moduleCards = orderedEntries(results, state && state.phaseOrder).map(([key, result]) => {
      const findings = Array.isArray(result && result.findings) ? result.findings : [];
      const findingHtml = findings.length
        ? findings.map(rawFinding => {
            const finding = normalizeFinding(rawFinding);
            return `
              <div class="finding ${riskClass(finding.type)}">
                <div class="finding-title">${escapeHtml(finding.type)}: ${escapeHtml(finding.title)}</div>
                ${finding.detail ? `<div class="finding-detail">${escapeHtml(finding.detail).replace(/\n/g, '<br>')}</div>` : ''}
              </div>`;
          }).join('')
        : '<div class="muted">No findings.</div>';
      return `
        <section class="card">
          <div class="module-header">
            <h2>${escapeHtml(phaseLabel(key, state && state.phaseMeta))}</h2>
            <span class="badge ${riskClass(result && result.risk_level)}">${escapeHtml(result && result.risk_level)} RISK</span>
          </div>
          <div class="module-score">${escapeHtml(result && result.score)} / 100</div>
          <p class="summary">${escapeHtml(result && result.summary)}</p>
          <div class="findings">${findingHtml}</div>
        </section>`;
    }).join('');

    const controlsHtml = controls.length ? `
      <section class="card">
        <h2>AppSec Security Controls</h2>
        ${controls.map(control => `
          <div class="control">
            <div class="control-title">${escapeHtml(control.priority || 'RECOMMEND')}: ${escapeHtml(control.title)}</div>
            ${control.category ? `<div><strong>Category:</strong> ${escapeHtml(control.category)}</div>` : ''}
            ${control.precondition ? `<div><strong>Precondition:</strong> ${escapeHtml(control.precondition)}</div>` : ''}
            ${control.reason ? `<div><strong>Reason:</strong> ${escapeHtml(control.reason)}</div>` : ''}
            ${control.implementation ? `<div><strong>Implementation:</strong> ${escapeHtml(control.implementation).replace(/\n/g, '<br>')}</div>` : ''}
            ${control.example ? `<pre><code>${escapeHtml(control.example)}</code></pre>` : ''}
          </div>
        `).join('')}
      </section>` : '';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Risk Report - ${escapeHtml(target)}</title>
  <style>
    body { font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }
    main { max-width: 1040px; margin: 0 auto; padding: 32px 20px; }
    .hero { background: linear-gradient(135deg, #0f172a, #312e81); color: white; padding: 28px; border-radius: 18px; margin-bottom: 20px; }
    .hero h1 { margin: 0 0 8px; font-size: 28px; }
    .meta { color: #cbd5e1; font-size: 13px; }
    .overall { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 18px; }
    .metric { background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.18); border-radius: 14px; padding: 14px; }
    .metric-label { color: #cbd5e1; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
    .metric-value { font-size: 24px; font-weight: 800; margin-top: 4px; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin-bottom: 16px; box-shadow: 0 8px 24px rgba(15,23,42,0.05); }
    .module-header { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
    h2 { margin: 0 0 8px; font-size: 18px; }
    .module-score { font-size: 22px; font-weight: 800; margin: 4px 0; }
    .summary, .muted { color: #64748b; font-size: 13px; }
    .badge { display: inline-block; border-radius: 999px; color: white; font-size: 12px; font-weight: 700; padding: 4px 10px; white-space: nowrap; }
    .critical { background: #dc2626; }
    .high { background: #ea580c; }
    .medium { background: #ca8a04; }
    .low { background: #16a34a; }
    .unknown { background: #94a3b8; }
    .finding { border-left: 4px solid #94a3b8; background: #f8fafc; border-radius: 8px; padding: 10px 12px; margin-top: 8px; }
    .finding.critical { border-left-color: #dc2626; background: #fef2f2; }
    .finding.high { border-left-color: #ea580c; background: #fff7ed; }
    .finding.medium { border-left-color: #ca8a04; background: #fefce8; }
    .finding.low { border-left-color: #16a34a; background: #f0fdf4; }
    .finding-title, .control-title { font-weight: 700; }
    .finding-detail, .control { color: #334155; font-size: 13px; line-height: 1.6; margin-top: 6px; }
    .control { border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 12px; }
    pre { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 10px; overflow-x: auto; }
    @media print { body { background: white; } .card, .hero { box-shadow: none; break-inside: avoid; } }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>AI Agent Risk Assessment Report</h1>
      <div class="meta">Repository: ${escapeHtml(target)} · Generated: ${escapeHtml(generatedAt)}</div>
      <div class="overall">
        <div class="metric"><div class="metric-label">Overall Score</div><div class="metric-value">${escapeHtml(overall.score)} / 100</div></div>
        <div class="metric"><div class="metric-label">Risk Level</div><div class="metric-value">${escapeHtml(overall.risk_level)}</div></div>
        <div class="metric"><div class="metric-label">Label</div><div class="metric-value">${escapeHtml(overall.label || '')}</div></div>
      </div>
    </section>
    ${moduleCards}
    ${controlsHtml}
  </main>
</body>
</html>`;
  }

  function buildHtmlSnapshotReport(state) {
    const target = text(state && state.target) || 'Unknown repository';
    const generatedAt = text(state && state.generatedAt) || new Date().toISOString();
    const contentHtml = text(state && state.contentHtml);
    const inlineStyles = text(state && state.inlineStyles);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Risk Report - ${escapeHtml(target)}</title>
  <script src="https://cdn.tailwindcss.com"><\/script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
${inlineStyles}
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; }
    .report-export-meta { max-width: 56rem; margin: 1.5rem auto 0; padding: 0 1rem; color: #64748b; font-size: 12px; }
    @media print { .card, details { break-inside: avoid; } }
  </style>
</head>
<body class="min-h-screen bg-gray-50">
  <div class="report-export-meta">Repository: ${escapeHtml(target)} · Exported: ${escapeHtml(generatedAt)}</div>
  <main id="exportedReport">
${contentHtml}
  </main>
  <script>
    function toggleDimCard(bodyId, chevId) {
      const body = document.getElementById(bodyId);
      const chev = document.getElementById(chevId);
      if (!body) return;
      const collapsed = body.classList.toggle('hidden');
      if (chev) chev.style.transform = collapsed ? 'rotate(180deg)' : '';
    }
    function toggleFinding(id) {
      const el = document.getElementById(id);
      const icon = document.getElementById(id + '-icon');
      if (!el) return;
      const isOpen = !el.classList.contains('hidden');
      if (isOpen) {
        el.classList.add('hidden');
        if (icon) icon.style.transform = 'rotate(0deg)';
      } else {
        el.classList.remove('hidden');
        if (icon) icon.style.transform = 'rotate(90deg)';
      }
    }
    function toggleFindings(id) {
      const el = document.getElementById(id);
      const icon = document.getElementById(id + '-icon');
      if (!el) return;
      const collapsed = el.classList.toggle('hidden');
      if (icon) icon.className = collapsed ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
    }
    function toggleSecurityCard() {
      const body = document.getElementById('securityCardBody');
      const chv = document.getElementById('securityCardChevron');
      if (!body) return;
      const collapsed = body.classList.toggle('hidden');
      if (chv) chv.style.transform = collapsed ? 'rotate(180deg)' : '';
    }
    function toggleCategory(id) {
      const el = document.getElementById(id);
      const chv = document.getElementById('cat-chevron-' + id);
      if (!el) return;
      const collapsed = el.classList.toggle('hidden');
      if (chv) chv.style.transform = collapsed ? 'rotate(180deg)' : '';
    }
    function toggleCtrl(id) {
      const el = document.getElementById(id);
      const chv = document.getElementById('chevron-' + id);
      if (!el) return;
      const collapsed = el.classList.toggle('hidden');
      if (chv) chv.style.transform = collapsed ? 'rotate(0deg)' : 'rotate(180deg)';
    }
  <\/script>
</body>
</html>`;
  }

  return {
    buildMarkdownReport,
    buildHtmlReport,
    buildHtmlSnapshotReport,
    stripHtml,
    reportFileStem,
  };
});
