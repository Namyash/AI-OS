import { act, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { FetchLike } from './services/api-client';
import { HEALTH_BODY, hangingFetch, jsonResponse, makeClient, TEST_TOKEN } from './test/fakes';

function renderApp(fetch: FetchLike, token: string | null = TEST_TOKEN) {
  return render(<App client={makeClient(fetch, { token })} />);
}

const healthy: FetchLike = async () => jsonResponse(HEALTH_BODY);

describe('App shell: truthful state', () => {
  it('shows the backend as connected, with its version, once /health answers', async () => {
    renderApp(healthy);

    expect(await screen.findByText('Backend connected')).toBeInTheDocument();
    expect(screen.getByText('Version 0.0.1')).toBeInTheDocument();
  });

  it('shows the backend as connecting while the first answer is pending', () => {
    renderApp(hangingFetch);

    expect(screen.getByText('Backend connecting')).toBeInTheDocument();
  });

  it('shows the backend as unreachable, and says it is retrying, when the request fails', async () => {
    renderApp(() => Promise.reject(new TypeError('Failed to fetch')));

    expect(await screen.findByText('Backend unreachable')).toBeInTheDocument();
    expect(screen.getByText('Connection failed. Retrying.')).toBeInTheDocument();
  });

  it('shows a rejected token when the backend answers 401', async () => {
    renderApp(async () => jsonResponse({ error: { code: 'invalid_token', message: 'Bad token.' } }, 401));

    expect(await screen.findByText('Access token rejected')).toBeInTheDocument();
  });

  it('shows a missing token when the page was opened without one', async () => {
    const fetch = vi.fn<FetchLike>(healthy);

    renderApp(fetch, null);

    expect(await screen.findByText('Access token missing')).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('labels the network state as reported by the browser and follows it', async () => {
    renderApp(healthy);
    expect(screen.getByText('Browser reports online')).toBeInTheDocument();

    act(() => {
      vi.spyOn(window.navigator, 'onLine', 'get').mockReturnValue(false);
      window.dispatchEvent(new Event('offline'));
    });

    expect(screen.getByText('Browser reports offline')).toBeInTheDocument();
    await screen.findByText('Backend connected'); // let the pending health check settle inside act
  });

  it('says "No model loaded" in the header, with the reason', () => {
    renderApp(healthy);

    const header = within(screen.getByRole('banner'));
    expect(header.getByRole('heading', { level: 1, name: 'Private AI OS' })).toBeInTheDocument();
    expect(header.getByText('No model loaded')).toBeInTheDocument();
    expect(header.getByText('Model support is not part of this build yet.')).toBeInTheDocument();
  });

  it('keeps the access token out of the page', async () => {
    renderApp(healthy);
    await screen.findByText('Backend connected');

    expect(document.body.innerHTML).not.toContain(TEST_TOKEN);
  });
});

describe('App shell: conversation and composer', () => {
  it('says in the conversation area that the assistant is not available yet, and why', () => {
    renderApp(healthy);

    const main = within(screen.getByRole('main', { name: 'Conversation' }));
    expect(main.getByRole('heading', { level: 2, name: 'The assistant is not available yet.' })).toBeInTheDocument();
    expect(main.getByText(/no model to talk to/)).toBeInTheDocument();
  });

  it('promises no guarantee that this build does not have: approvals, where data lives, what runs where', () => {
    renderApp(healthy);

    // There is no approval flow, storage, memory or model runtime yet. Wording like this may appear once the feature
    // exists and a test exercises it (THREAT_MODEL section 3, PHASE1_PLAN definition of done), not before.
    const unbuiltGuarantees = /approv|cloud|stored|memory|encrypt|locally|\bsecure|\bsafe\b|\bprivate data/i;
    const visibleText = document.body.textContent ?? '';

    expect(visibleText).not.toMatch(unbuiltGuarantees);
    expect(visibleText).toContain('The assistant is not available yet.'); // the page was rendered and read
  });

  it('disables the message box and the send button and shows why', () => {
    renderApp(healthy);

    const box = screen.getByRole('textbox', { name: 'Message' });
    expect(box).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
    expect(screen.getByText('Messaging is off until a model is loaded.')).toBeVisible();
    expect(box).toHaveAccessibleDescription('Messaging is off until a model is loaded.');
  });

  it('cannot be focused, so nothing can be typed or sent, while disabled', () => {
    renderApp(healthy);
    const box = screen.getByRole('textbox', { name: 'Message' });
    const send = screen.getByRole('button', { name: 'Send' });

    // A disabled control refuses focus and so never receives keystrokes. Styling that only looks disabled, or
    // aria-disabled alone, would take focus here and fail.
    box.focus();
    expect(box).not.toHaveFocus();
    send.focus();
    expect(send).not.toHaveFocus();
    expect(box).toHaveValue('');
  });

  it('offers nothing for features that do not exist: no navigation, links, settings or extra controls', () => {
    renderApp(healthy);

    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    expect(screen.queryAllByRole('link')).toHaveLength(0);
    expect(screen.getAllByRole('button').map((button) => button.textContent)).toEqual(['Send']);
    expect(screen.getAllByRole('textbox')).toHaveLength(1);
  });

  it('has one landmark for each part of the shell, and a named status region', () => {
    renderApp(healthy);

    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'System status' })).toBeInTheDocument();
  });
});
