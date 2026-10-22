import type { Report } from '../types.js';
import { MARKDOWN_MARKER, renderMarkdown, type MarkdownOptions } from './markdown.js';
import { renderPretty, type PrettyOptions } from './pretty.js';
import { renderSarif, type SarifOptions } from './sarif.js';

export type ReportFormat = 'pretty' | 'json' | 'markdown' | 'sarif';

export const REPORT_FORMATS: readonly ReportFormat[] = ['pretty', 'json', 'markdown', 'sarif'];

export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2) + '\n';
}

export type FormatOptions = PrettyOptions & MarkdownOptions & SarifOptions;

/** Renders a report in any supported format. */
export function formatReport(report: Report, format: ReportFormat = 'pretty', options: FormatOptions = {}): string {
  switch (format) {
    case 'pretty':
      return renderPretty(report, options);
    case 'json':
      return renderJson(report);
    case 'markdown':
      return renderMarkdown(report, options);
    case 'sarif':
      return renderSarif(report, options);
  }
}

export { MARKDOWN_MARKER, renderMarkdown, renderPretty, renderSarif };
