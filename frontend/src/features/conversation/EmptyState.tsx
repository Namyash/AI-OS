import { useId } from 'react';

/**
 * Shown while there are no messages. It says only what is true of this build: there is no model, so there is
 * nothing to talk to. Wording that promises a guarantee (approvals, where data lives, what runs where) belongs
 * here only once the feature exists and a test exercises it (THREAT_MODEL section 3, PHASE1_PLAN definition of done).
 */
export function EmptyState() {
  const headingId = useId();
  return (
    <section className="empty-state" aria-labelledby={headingId}>
      <h2 id={headingId} className="empty-state__heading">
        The assistant is not available yet.
      </h2>
      <p className="empty-state__intro">
        This build has no model to talk to, so there is nothing to ask yet. The status bar below shows whether the
        backend is running.
      </p>
    </section>
  );
}
