# Tool Execution and Authorization Model

The LLM proposes; deterministic code authorizes and executes. The model never receives a handle that can act on the system.

## 1. Permission levels

| Level | Meaning | Examples | Default policy |
|---|---|---|---|
| 1 | Read-only | list files, system info, search documents | Auto-allowed inside granted scopes |
| 2 | Reversible | create folder/document, user-level package install | Auto-allowed in granted scopes unless the turn is **tainted** |
| 3 | Sensitive | delete files, edit system config, firewall, permissions | Explicit approval with preview |
| 4 | Critical | format disk, change encryption/auth, delete large datasets | Approval with typed confirmation and a cooling step; never auto-allowed |

A tool declares its **maximum** level; the policy engine may raise it from arguments (e.g. `delete_path` on more than N files or on a
path outside the user's home becomes level 4). The engine, not the model, computes the effective level.

## 2. Tool contract

```
Tool
├─ name, version, description
├─ InputModel / OutputModel          (Pydantic, extra="forbid")
├─ level(args) -> 1..4               (deterministic)
├─ preview(args) -> Preview          (exact effects, no side effects)
├─ execute(args, ctx) -> Output
├─ verify(args, output) -> Verification   (re-observes the world: file exists, hash matches, service active)
└─ rollback_hint(args, output)       (trash location, previous value) when reversible
```

No tool accepts free-form shell text. Shell-like capabilities are narrow typed tools; a general `run_command` exists only at level 4.

## 3. Execution pipeline

1. **Parse** model output into a plan (structured output; see compatibility layer). Invalid → bounded repair loop → fail closed.
2. **Validate** each step against the registry schema. Unknown tool or extra field → rejected.
3. **Classify** effective level and taint (did any untrusted content influence this turn?).
4. **Authorize**: check `user_permissions` scopes; build the preview; if approval needed, create an `approvals` row bound to
   `SHA256(canonical_json(tool, version, args))`.
5. **Approve**: UI shows the preview; the decision is recorded with timestamp. Approvals are single-use and expire (default 10 min).
6. **Execute**: unprivileged tools run in the backend executor with per-execution timeouts and output caps. Privileged verbs are sent to
   `pai-privd` with the approval token; `pai-privd` recomputes the hash and refuses on mismatch.
7. **Verify**: run `verify()`. Success requires verification pass; otherwise the step is `failed` and recovery may retry (bounded) or replan.
8. **Record**: `tool_executions` row, `security_events` entry (hash-chained), task state updated.

## 4. Taint tracking (prompt-injection defence)

Every string entering the context is labelled: `user` (typed in the UI) or `untrusted` (file contents, web pages, tool output, retrieved
memories derived from them, model-generated text echoing them). A turn with any `untrusted` content is *tainted*:
- Level ≥ 2 steps always require approval, and the preview shows which sources were in context.
- Policy text is never placed in the model's control and cannot be changed by model output.
- Instructions found in untrusted content are data: the system prompt states this, but enforcement does not rely on the model obeying it.

## 5. Structured output / tool-call compatibility layer

Capabilities are probed per model and stored in `models.capabilities_json`. Strategy order:
1. Native tool calls via the model's chat template (when the probe round-trips a test call correctly).
2. Grammar-constrained JSON (llama.cpp GBNF / JSON-schema) generated from the tool registry.
3. Prompted JSON with strict validation, a bounded repair loop (default 2 retries), then fail closed.
The orchestrator only sees a validated `Plan`, independent of strategy.

## 6. Recovery and interruption

- Task and step status persisted before and after every step; the executor is a resumable state machine.
- On boot, tasks left `running` become `interrupted`. The user can resume (re-verify completed steps, continue pending) or abandon.
- Retries only for steps whose tool declares itself idempotent; otherwise ask or replan.
- Cancel: cooperative flag checked between steps and inside long tools; running subprocesses get SIGTERM then SIGKILL after a grace period.
