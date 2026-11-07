# Memory Architecture

All memory lives on the LUKS volume under `/var/lib/pai`. It survives restarts and model changes because nothing in it depends on the
loaded model, except embeddings, which are tagged with the embedder that produced them and can be rebuilt.

| Memory | Storage | Lifetime | Written by |
|---|---|---|---|
| Episodic | `conversations`, `messages` (+ FTS5) | until the user deletes | conversation manager |
| Semantic | `memories`, `memory_sources` (+ FTS5, vectors) | until deleted/expired/superseded | memory writer (gated) |
| Working | in-process object persisted to `tasks.working_state_json` | active task/conversation | orchestrator |
| Task | `tasks`, `task_steps`, `tool_executions` | until deleted | task manager |
| Knowledge | `documents`, `document_chunks`, vectors, FTS5 | until removed | document engine |

## Semantic memory write policy

1. **Candidate extraction** runs after a turn (never blocks the reply) and proposes `{content, category, confidence, importance, sources}`.
2. **Gate** (deterministic): drop if memory extraction is paused or the category is disabled; drop and flag if a secret/credential/PII
   detector fires (credentials go to `pai-secretd` only after an explicit user action); drop duplicates by embedding+text similarity
   (update `last_updated`, merge sources instead).
3. **Provenance**: `origin` is `user_stated`, `model_inferred` or `user_edited`. Model-inferred memories with confidence < 0.7 are stored
   `pending_review`, are never injected as facts, and are surfaced for the user to confirm or reject.
4. **Contradictions**: a newer contradicting memory sets `superseded_by` on the older one rather than deleting it.
5. **Expiry**: optional `expires_at` per category policy; expired memories are excluded from retrieval and purged by a maintenance job.

## Retrieval and context budget

Per request the context manager has a token budget `B = context_length − reserved_output − system − tools`, split roughly:
recent turns 40%, conversation summary 10%, memories 20%, knowledge chunks 25%, slack 5% (tunable settings).

1. Build a query from the current message plus a rewritten standalone form using recent turns.
2. Candidates: vector top-k and FTS5 top-k for memories and chunks (hybrid), filtered by user, project and `status='active'`.
3. Score `0.55·similarity + 0.15·recency_decay + 0.20·importance + 0.10·project_match`; apply MMR to reduce near-duplicates.
4. Fill the budget greedily by score; each knowledge chunk keeps its `document_id` and location so answers can cite sources.
5. Retrieved text is labelled `untrusted` for taint tracking when it originated from documents or tool output.

Older conversation turns are compressed into `conversations.summary` by rolling summarisation (the summary is regenerated, not appended
forever) so the full history is never sent to the model.

## Knowledge pipeline

watch/add → hash (skip unchanged) → extract text (PDF/DOCX/XLSX/text; extractors run in a sandboxed subprocess) → chunk (structure-aware,
≈ 300–500 tokens, 10–15 % overlap, page/section kept) → embed (local embedder, batched) → write chunks + vectors in one transaction →
mark `indexed`. Re-embedding on embedder change is a background job keyed by `embedder` in `chunk_embeddings`.

## User control

Memory view/search/edit/delete, per-category toggles, pause extraction, delete conversation (with an option to delete derived
memories; otherwise `memory_sources` keeps the memory and shows "source deleted"), export to JSON/Markdown.
Settings live in `app_settings` (`memory.extraction_enabled`, `memory.categories`, budgets).

## Vector store interface

```
VectorStore.upsert(collection, id, vector, payload) · delete(collection, ids) · search(collection, vector, k, filter) · count(collection)
```
Phase 4 benchmarks sqlite-vec and Qdrant; the choice is recorded in an ADR. Vectors are derived data and can always be rebuilt from text.
