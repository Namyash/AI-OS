import { useSyncExternalStore } from 'react';

function subscribe(onChange: () => void): () => void {
  window.addEventListener('online', onChange);
  window.addEventListener('offline', onChange);
  return () => {
    window.removeEventListener('online', onChange);
    window.removeEventListener('offline', onChange);
  };
}

function getSnapshot(): boolean {
  return navigator.onLine;
}

/**
 * What the browser reports through `navigator.onLine` and the `online` / `offline` events.
 *
 * This is the browser's view only: `true` means it believes a network interface is up, not that anything beyond
 * this computer is reachable (the OS blocks outbound traffic by default), and `false` does not mean the backend
 * is down. The UI labels it "reported by the browser" for that reason.
 */
export function useBrowserOnline(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot);
}
