/** What the UI says about the local language model. All model-related wording lives here. */
export interface ModelStatus {
  /** Short state shown in the header. */
  label: string;
  /** Why this is the state, in plain words. */
  reason: string;
  /** Why the message box is unavailable, shown next to it. */
  messagingReason: string;
}

/**
 * The only state that exists today: the model runtime starts in Phase 2 (see PHASE1_PLAN.md, "Out of scope") and
 * the backend has no model endpoint yet. When it does, this becomes data read through `services/` and this
 * constant is replaced, not extended with flags for states nothing can produce.
 */
export const NO_MODEL: ModelStatus = {
  label: 'No model loaded',
  reason: 'Model support is not part of this build yet.',
  messagingReason: 'Messaging is off until a model is loaded.',
};
