const assert = require('assert');

const {
  buildMarkdownReport,
  buildHtmlReport,
  buildHtmlSnapshotReport,
  stripHtml,
  reportFileStem,
} = require('../static/report_exporter.js');

const sampleState = {
  target: 'owner/repo',
  generatedAt: '2026-06-24T09:00:00.000Z',
  language: 'en',
  overall: {
    score: 82.5,
    risk_level: 'LOW',
    label: 'Low Risk',
    excluded_modules: ['deps'],
  },
  results: {
    code: {
      score: 75,
      risk_level: 'LOW',
      summary: '1 LLM-controlled capability',
      findings: [
        {
          type: 'INFO',
          title: '📊 Score Breakdown — Final: <b>75</b> / 100',
          detail: '<div>Terminal/Shell <b>-25</b></div>',
          is_html: true,
        },
        {
          type: 'HIGH',
          title: '⚠️ Shell execution',
          detail: 'LLM controls command text',
        },
      ],
    },
    skill: {
      score: 100,
      risk_level: 'LOW',
      summary: 'No malicious skill findings',
      findings: [],
    },
  },
  controls: [
    {
      category: 'Capability Boundary Controls',
      title: 'Restrict shell commands',
      priority: 'MUST',
      precondition: 'If shell execution is enabled',
      reason: 'The model can request arbitrary commands.',
      implementation: 'Add an allowlist before command execution.',
      example: 'const allowed = ["git", "ls"];',
    },
  ],
  phaseOrder: ['code', 'skill'],
  phaseMeta: {
    code: { icon: '🤖', label: 'Agent Capability / Blast Radius' },
    skill: { icon: '🔧', label: 'Skill Security Quality' },
  },
};

function testMarkdownReport() {
  const markdown = buildMarkdownReport(sampleState);

  assert(markdown.startsWith('# AI Agent Risk Assessment Report'));
  assert(markdown.includes('**Repository:** owner/repo'));
  assert(markdown.includes('| Overall Score | 82.5 / 100 |'));
  assert(markdown.includes('## Module Results'));
  assert(markdown.includes('### 🤖 Agent Capability / Blast Radius'));
  assert(markdown.includes('#### HIGH: ⚠️ Shell execution'));
  assert(markdown.includes('Terminal/Shell -25'));
  assert(markdown.includes('## AppSec Security Controls'));
  assert(markdown.includes('### MUST: Restrict shell commands'));
  assert(!markdown.includes('<div>'));
  assert(!markdown.includes('<b>'));
}

function testHtmlReport() {
  const html = buildHtmlReport(sampleState);

  assert(html.startsWith('<!DOCTYPE html>'));
  assert(html.includes('<title>AI Risk Report - owner/repo</title>'));
  assert(html.includes('owner/repo'));
  assert(html.includes('82.5 / 100'));
  assert(html.includes('Agent Capability / Blast Radius'));
  assert(html.includes('Restrict shell commands'));
  assert(html.includes('const allowed = [&quot;git&quot;, &quot;ls&quot;];'));
}

function testHtmlSnapshotReportPreservesPageDomAndInteractions() {
  const html = buildHtmlSnapshotReport({
    target: 'owner/repo',
    generatedAt: '2026-06-24T09:00:00.000Z',
    contentHtml: '<div id="overallCard" class="card p-8"><button onclick="toggleFinding(\'f-1\')">Expand</button><div id="f-1" class="hidden finding-HIGH">Finding</div></div>',
    inlineStyles: '.card { border-radius: 1rem; }',
  });

  assert(html.startsWith('<!DOCTYPE html>'));
  assert(html.includes('https://cdn.tailwindcss.com'));
  assert(html.includes('cdnjs.cloudflare.com/ajax/libs/font-awesome'));
  assert(html.includes('id="overallCard" class="card p-8"'));
  assert(html.includes('onclick="toggleFinding(\'f-1\')"'));
  assert(html.includes('function toggleFinding(id)'));
  assert(html.includes('.card { border-radius: 1rem; }'));
  assert(!html.includes('Export HTML Report'));
}

function testHelpers() {
  assert.strictEqual(stripHtml('<div>Hello&nbsp;<b>World</b></div>'), 'Hello World');
  assert.strictEqual(reportFileStem('owner/repo name'), 'ai-risk-report-owner_repo-name');
}

testMarkdownReport();
testHtmlReport();
testHtmlSnapshotReportPreservesPageDomAndInteractions();
testHelpers();

console.log('report_exporter tests passed');
