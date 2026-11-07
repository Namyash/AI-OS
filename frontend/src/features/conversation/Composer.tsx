import { useId } from 'react';
import { StateMark } from '../../components/StateMark';

/**
 * The message box, turned off with its reason shown beside it. It is disabled for real (not styled to look
 * disabled) and takes no submit handler: sending arrives together with the model runtime, and until then there
 * is nothing it could honestly do.
 */
export function Composer({ disabledReason }: { disabledReason: string }) {
  const reasonId = useId();
  return (
    <div className="composer">
      <div className="composer__field">
        <textarea
          className="composer__input"
          aria-label="Message"
          aria-describedby={reasonId}
          placeholder="Message the assistant"
          rows={2}
          disabled
        />
        <button className="composer__send" type="button" disabled>
          Send
        </button>
      </div>
      <p id={reasonId} className="composer__reason">
        <StateMark kind="ring" />
        {disabledReason}
      </p>
    </div>
  );
}
