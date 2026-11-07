import './StateMark.css';

/**
 * A small status glyph. Shape carries the meaning so that no state depends on colour alone:
 *
 * - `solid`: present or working
 * - `ring`: absent or empty, not an error
 * - `dashed`: in progress or waiting (turns slowly unless the user prefers reduced motion)
 * - `slashed`: failed, will retry
 * - `barred`: refused, needs the user to act
 */
export type StateMarkKind = 'solid' | 'ring' | 'dashed' | 'slashed' | 'barred';

export function StateMark({ kind }: { kind: StateMarkKind }) {
  return (
    <svg className={`state-mark state-mark--${kind}`} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      {kind === 'solid' ? (
        <circle cx="8" cy="8" r="5.5" fill="currentColor" />
      ) : (
        <circle
          cx="8"
          cy="8"
          r="5"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeDasharray={kind === 'dashed' ? '3.1 3.1' : undefined}
        />
      )}
      {kind === 'slashed' && (
        <line x1="3.5" y1="12.5" x2="12.5" y2="3.5" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
      )}
      {kind === 'barred' && (
        <line x1="5" y1="8" x2="11" y2="8" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
      )}
    </svg>
  );
}
