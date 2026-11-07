import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useBrowserOnline } from './useBrowserOnline';

function setReportedOnline(value: boolean): void {
  vi.spyOn(window.navigator, 'onLine', 'get').mockReturnValue(value);
}

describe('useBrowserOnline', () => {
  it('starts with what the browser reports', () => {
    setReportedOnline(false);

    const { result } = renderHook(() => useBrowserOnline());

    expect(result.current).toBe(false);
  });

  it('follows the browser online and offline events', () => {
    setReportedOnline(true);
    const { result } = renderHook(() => useBrowserOnline());
    expect(result.current).toBe(true);

    act(() => {
      setReportedOnline(false);
      window.dispatchEvent(new Event('offline'));
    });
    expect(result.current).toBe(false);

    act(() => {
      setReportedOnline(true);
      window.dispatchEvent(new Event('online'));
    });
    expect(result.current).toBe(true);
  });

  it('stops listening on unmount', () => {
    const remove = vi.spyOn(window, 'removeEventListener');
    const { unmount } = renderHook(() => useBrowserOnline());

    unmount();

    expect(remove).toHaveBeenCalledWith('online', expect.any(Function));
    expect(remove).toHaveBeenCalledWith('offline', expect.any(Function));
  });
});
