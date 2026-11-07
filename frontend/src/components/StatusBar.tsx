import type { BackendHealth } from '../hooks/useBackendHealth';
import './StatusBar.css';
import { StateMark, type StateMarkKind } from './StateMark';

interface StatusLine {
  mark: StateMarkKind;
  /** Drives the mark colour; the words and the mark shape say the same thing without colour. */
  tone: 'quiet' | 'attention' | 'danger';
  label: string;
  detail: string | null;
}

function unreachableDetail(health: Extract<BackendHealth, { status: 'unreachable' }>): string {
  switch (health.cause) {
    case 'network':
      return 'Connection failed.';
    case 'timeout':
      return 'No reply in time.';
    case 'http':
      return health.httpStatus === null ? 'It replied with an error.' : `It replied with error ${health.httpStatus}.`;
    case 'invalid-response':
      return 'It sent an unexpected reply.';
    case 'unexpected':
      return 'The interface hit an unexpected error.';
  }
}

function describeBackend(health: BackendHealth): StatusLine {
  switch (health.status) {
    case 'connecting':
      return { mark: 'dashed', tone: 'quiet', label: 'Backend connecting', detail: null };
    case 'connected':
      return { mark: 'solid', tone: 'quiet', label: 'Backend connected', detail: `Version ${health.health.version}` };
    case 'unreachable':
      return {
        mark: 'slashed',
        tone: 'attention',
        label: 'Backend unreachable',
        detail: `${unreachableDetail(health)} Retrying.`,
      };
    case 'unauthorized':
      return {
        mark: 'barred',
        tone: 'danger',
        label: health.cause === 'no-token' ? 'Access token missing' : 'Access token rejected',
        detail: 'Restart the interface to get a new one.',
      };
  }
}

interface StatusBarProps {
  backend: BackendHealth;
  /** What the browser reports (`navigator.onLine`); not a test of any connection. */
  browserOnline: boolean;
}

/**
 * Connection facts, each backed by real data. Each line is a polite live region, so a change (for example the
 * backend going away) is announced to screen readers without moving focus.
 */
export function StatusBar({ backend, browserOnline }: StatusBarProps) {
  const backendLine = describeBackend(backend);
  return (
    <section className="status-bar" aria-label="System status">
      <div className="status-bar__inner">
        <div className="status-line" role="status" data-tone={backendLine.tone}>
          <StateMark kind={backendLine.mark} />
          <span>{backendLine.label}</span>{' '}
          {backendLine.detail !== null && <span className="status-line__detail">{backendLine.detail}</span>}
        </div>
        <div className="status-line" role="status" data-tone="quiet">
          <StateMark kind={browserOnline ? 'solid' : 'ring'} />
          <span>{browserOnline ? 'Browser reports online' : 'Browser reports offline'}</span>
        </div>
      </div>
    </section>
  );
}
