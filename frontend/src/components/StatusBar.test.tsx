import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { BackendHealth } from '../hooks/useBackendHealth';
import { StatusBar } from './StatusBar';

function backendLine(): HTMLElement {
  const [line] = screen.getAllByRole('status');
  if (!line) {
    throw new Error('no status line rendered');
  }
  return line;
}

describe('StatusBar backend line', () => {
  const cases: Array<[string, BackendHealth, string, string | null]> = [
    ['connecting', { status: 'connecting' }, 'Backend connecting', null],
    [
      'connected',
      { status: 'connected', health: { status: 'ok', schema_version: 1, version: '2.4.1' } },
      'Backend connected',
      'Version 2.4.1',
    ],
    [
      'unreachable: connection failed',
      { status: 'unreachable', cause: 'network', httpStatus: null },
      'Backend unreachable',
      'Connection failed. Retrying.',
    ],
    [
      'unreachable: timeout',
      { status: 'unreachable', cause: 'timeout', httpStatus: null },
      'Backend unreachable',
      'No reply in time. Retrying.',
    ],
    [
      'unreachable: error status',
      { status: 'unreachable', cause: 'http', httpStatus: 503 },
      'Backend unreachable',
      'It replied with error 503. Retrying.',
    ],
    [
      'unreachable: unexpected reply',
      { status: 'unreachable', cause: 'invalid-response', httpStatus: 200 },
      'Backend unreachable',
      'It sent an unexpected reply. Retrying.',
    ],
    [
      'unreachable: the check itself failed',
      { status: 'unreachable', cause: 'unexpected', httpStatus: null },
      'Backend unreachable',
      'The interface hit an unexpected error. Retrying.',
    ],
    [
      'unauthorized: token rejected',
      { status: 'unauthorized', cause: 'rejected' },
      'Access token rejected',
      'Restart the interface to get a new one.',
    ],
    [
      'unauthorized: no token',
      { status: 'unauthorized', cause: 'no-token' },
      'Access token missing',
      'Restart the interface to get a new one.',
    ],
  ];

  it.each(cases)('says the truth for %s', (_name, backend, label, detail) => {
    render(<StatusBar backend={backend} browserOnline />);

    const line = within(backendLine());
    expect(line.getByText(label)).toBeInTheDocument();
    if (detail === null) {
      expect(backendLine().textContent?.trim()).toBe(label);
    } else {
      expect(line.getByText(detail)).toBeInTheDocument();
    }
  });

  describe('when the state changes', () => {
    const bar = (backend: BackendHealth) => (
      <>
        <button type="button">Elsewhere</button>
        <StatusBar backend={backend} browserOnline />
      </>
    );

    it('updates the same live regions in place, so a screen reader announces the new text', () => {
      const { rerender } = render(bar({ status: 'connecting' }));
      const before = screen.getAllByRole('status');

      rerender(bar({ status: 'unreachable', cause: 'network', httpStatus: null }));

      const after = screen.getAllByRole('status');
      expect(after).toHaveLength(2);
      // The same elements, not replacements: a live region added together with its text is often not announced.
      expect(after[0]).toBe(before[0]);
      expect(after[1]).toBe(before[1]);
      expect(after[0]).toHaveTextContent('Backend unreachable');
    });

    it('announces politely: the live regions are never assertive or switched off', () => {
      render(bar({ status: 'unauthorized', cause: 'rejected' }));

      for (const line of screen.getAllByRole('status')) {
        // No explicit aria-live means the role's own default, which is polite.
        expect(line.getAttribute('aria-live') ?? 'polite').toBe('polite');
      }
    });

    it('does not take focus from whatever the user is on', () => {
      const { rerender } = render(bar({ status: 'connecting' }));
      const elsewhere = screen.getByRole('button', { name: 'Elsewhere' });
      elsewhere.focus();

      rerender(bar({ status: 'unreachable', cause: 'timeout', httpStatus: null }));

      expect(elsewhere).toHaveFocus();
    });
  });
});

describe('StatusBar browser line', () => {
  it('labels the state as reported by the browser, online or offline', () => {
    const { rerender } = render(<StatusBar backend={{ status: 'connecting' }} browserOnline />);
    expect(screen.getByText('Browser reports online')).toBeInTheDocument();

    rerender(<StatusBar backend={{ status: 'connecting' }} browserOnline={false} />);
    expect(screen.getByText('Browser reports offline')).toBeInTheDocument();
    expect(screen.queryByText('Browser reports online')).not.toBeInTheDocument();
  });
});
