import type { DocumentModeId } from './types';

export interface DocumentModeDefinition {
  id: DocumentModeId;
  label: string;
  description: string;
}

export const documentModes: DocumentModeDefinition[] = [
  {
    id: 'cli-config',
    label: 'CLI/config',
    description: 'Router, switch, firewall, and shell output.'
  },
  {
    id: 'markdown',
    label: 'Markdown',
    description: 'Markdown notes, runbooks, and incident summaries.'
  },
  {
    id: 'json',
    label: 'JSON',
    description: 'Pasted JSON payloads and structured logs.'
  },
  {
    id: 'yaml',
    label: 'YAML',
    description: 'YAML snippets, inventories, and configuration.'
  },
  {
    id: 'csv-log',
    label: 'CSV/log',
    description: 'Delimited output, syslog excerpts, and tables.'
  },
  {
    id: 'ticket-email',
    label: 'Ticket/email',
    description: 'Support cases, customer updates, and escalation notes.'
  }
];

export function getDocumentModeLabel(modeId: DocumentModeId): string {
  return documentModes.find((mode) => mode.id === modeId)?.label ?? 'CLI/config';
}
