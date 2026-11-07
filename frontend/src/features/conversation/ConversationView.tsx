import type { ModelStatus } from '../model/modelStatus';
import './conversation.css';
import { Composer } from './Composer';
import { EmptyState } from './EmptyState';

/** The primary surface. There are no messages yet, so the empty state fills the scrolling area above the composer. */
export function ConversationView({ model }: { model: ModelStatus }) {
  return (
    <main className="conversation" aria-label="Conversation">
      <div className="conversation__column">
        <div className="conversation__scroll">
          <EmptyState />
        </div>
        <Composer disabledReason={model.messagingReason} />
      </div>
    </main>
  );
}
