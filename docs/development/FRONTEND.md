# Frontend

Status: milestone M1.4a, the interface shell. The application builds, is tested, and has been run in Chromium through the
`npm run preview` proxy against the real backend (see [Verification record](#verification-record)). The backend does not serve
it yet and it has not been shown in the kiosk; both are the rest of M1.4. Nothing here changes what
[DEVELOPMENT_STATUS.md](../../DEVELOPMENT_STATUS.md) says works end to end.

## What it is

A React + TypeScript single-page app in `frontend/`. The backend will serve `frontend/dist/` from the site root and
Chromium will run it full-screen in a kiosk (see [ARCHITECTURE](../architecture/ARCHITECTURE.md) §3); neither exists yet. It shows
only what is backed by real data:

| Area | What is real | What is deliberately absent |
|---|---|---|
| Header | Product name. Model indicator: "No model loaded" with the reason. | Model picker, settings, account menu. |
| Conversation | An empty state saying the assistant is not available yet and why; a message box that is **disabled** with its reason beside it. | Messages, history, sending. The model runtime starts in Phase 2. Any statement about approvals, where data lives or what runs where: those appear with the features that make them true. |
| Status bar | Backend state from `GET /health`; the browser's own online/offline report, labelled as such. | Anything the backend cannot tell us yet. |
| Navigation | None. | Memory, files, tasks and settings screens: they appear with the features behind them. |

## Setup

Requires Node >= 20.18.1 (developed on 20.18.1). There is no npm minimum: use the npm that comes with your Node. Debian 13,
the base of the image, packages Node 20 with npm 9, and `npm ci`, the tests and the build were run on that pair (see
[Verification record](#verification-record)). Run npm only inside `frontend/`.

```bash
cd frontend
npm ci            # exact versions from package-lock.json
npm test          # unit and contract tests
npm run build     # typecheck, then production build into frontend/dist
```

`frontend/.npmrc` makes the install strict: `engine-strict=true` (a package that does not support the Node in use fails the
install instead of warning), `save-exact=true` (no `^` ranges) and `ignore-scripts=true` (no dependency may run install
scripts; supply-chain control T12 in the [threat model](../security/THREAT_MODEL.md)). Because `engine-strict` is on, a bound
in `engines` that the image's own tools do not meet aborts `npm ci`, which is why `engines` names Node only.

### Scripts

| Script | Does |
|---|---|
| `npm run dev` | Vite dev server on `127.0.0.1:5173` with hot reload; forwards backend paths to the backend (below). |
| `npm run build` | `typecheck`, then `vite build` into `dist/`. Does not read the proxy settings. |
| `npm run preview` | Serves `dist/` on `127.0.0.1:4173` with the production security headers and the same backend forwarding. Run `npm run build` first. |
| `npm run typecheck` | `tsc` for the app (`tsconfig.json`) and for the build and test tooling (`tsconfig.node.json`). Strict mode plus `noUncheckedIndexedAccess`. |
| `npm test` | Vitest, once, configured in `vitest.config.ts`. `npm run test:watch` watches. |
| `npm run lint` | Biome: lint (including accessibility and React-hooks rules), format check and import order. `npm run lint:fix` applies fixes. |

### Backend during development

`npm run dev` and `npm run preview` forward the paths in `BACKEND_PATHS` (`backend-proxy.ts`; today only `/health`) to the
backend named by the environment variable `PAI_BACKEND_URL`. When it is unset the target is `http://127.0.0.1:8765`, the address
the backend listens on when `PAI_HOST` and `PAI_PORT` are unset (`DEFAULT_PORT` in `backend/core/config.py`; a test keeps the
two equal). If you start the backend with another `PAI_PORT`, set `PAI_BACKEND_URL` to match, in the shell or in `frontend/.env`
(copy `frontend/.env.example`).

The backend generates a new access token every time it starts and writes it to `PAI_TOKEN_FILE`; nothing else creates or
supplies one (see [API_DOCUMENTATION](API_DOCUMENTATION.md)). The defaults for that file and for `PAI_DATA_DIR` are the
image's Linux paths, so on a development machine point both at folders you own, as absolute paths:

```bash
# terminal 1, from the repository root: the real backend. The token file is replaced at every start.
PAI_DATA_DIR=/abs/path/pai-data PAI_TOKEN_FILE=/abs/path/pai-token python -m backend

# terminal 2
cd frontend && npm run dev
```

Then open `http://127.0.0.1:5173/` with `#token=` and the contents of the token file added to the address. Copy the value from
the file into the address bar; do not put it on a command line, where every local account can read it. When the backend
restarts the old token stops working and the page shows "Access token rejected": open the page again with the new one.

The variable is read by the build tooling only and is never placed in the browser bundle. It must point at this computer
(`127.0.0.1`, `localhost` or `[::1]`) because the proxy forwards the access token: anything else makes the dev and preview
servers refuse to start. `npm run build` and `npm test` do not use the proxy and ignore the variable. Add a path to
`BACKEND_PATHS` when the backend gains an endpoint the UI uses. The dev server relaxes nothing in the app, but Vite's hot-reload
client needs inline script, so the strict policy below is applied by `npm run preview`, not `npm run dev`.

## Structure

```
frontend/
  index.html               entry page: no inline script, no external resource
  backend-proxy.ts         the dev/preview proxy target, its default and the loopback-only guard
  security-headers.ts      the Content-Security-Policy and headers (single source; see below)
  vite.config.ts           build, dev/preview servers and proxy
  vitest.config.ts         test runner configuration (kept apart so tests never load the proxy settings)
  biome.json               lint and format rules
  public/                  favicon and the font licence, copied into dist/
  src/
    main.tsx               startup: capture token, create client, render
    App.tsx                the shell: header, conversation, status bar
    services/              the only place the UI performs I/O
      token.ts             read the token from the URL fragment and strip it
      api-client.ts        same-origin GET with bearer token, timeout, typed errors
      api-error.ts         ApiError and its kinds
      health.ts            the /health type and its runtime type guard
      guards.ts            isRecord, shared by the guards
    hooks/                 useBackendHealth (polling with backoff), useBrowserOnline
    components/            AppHeader, StatusBar, StateMark
    features/
      conversation/        EmptyState, Composer (disabled), ConversationView
      model/               what the UI says about the model ("No model loaded")
    styles/                tokens.css (design tokens), base.css
    test/                  Vitest setup and shared fakes
  tests/                   checks that read files: privacy contract, layering, proxy guard, package contract, colour contrast
    support/               helpers that read and scan the source
```

Dependencies point one way, and `tests/architecture.test.ts` fails when they do not: `services` import only `services`; `hooks` import
`hooks` and `services`; `components` import `components` and `hooks` (a component receives plain props and never imports a
feature); `features` import `features`, `components`, `hooks` and `services`. `App.tsx` and `main.tsx` sit above all of them.

## Backend contract the UI relies on

Only this, nothing more:

- Every request carries `Authorization: Bearer <token>`.
- `GET /health` returns `{"status":"ok","schema_version":<integer>,"version":"<string>"}`. Extra fields are ignored. The
  version string must be 1 to 64 characters because it is displayed.
- Errors have the shape `{"error":{"code":"...","message":"..."}}`. The UI uses the HTTP status to decide what a failure
  means and keeps `code` for diagnostics; a body that is not this shape does not change the outcome.
- `401` means the token was refused.

The reply is checked at run time by the hand-written guard `isHealthResponse` (`services/health.ts`) because it comes from
outside the page. A reply that fails the check is treated as a failure (`unreachable`, cause "unexpected reply"), never as
"connected". Requests use `GET` only, with `credentials: 'omit'`, `cache: 'no-store'`, `referrerPolicy: 'no-referrer'` and
`redirect: 'error'`. A redirect is therefore an error, so `/health` must be served at exactly that path.

## Access token contract

1. **The backend owns the token.** It generates a fresh one every time it starts and writes it to `PAI_TOKEN_FILE` (in the image
   `/run/pai/token`, mode 0640, owner `pai`, group `pai`; the kiosk user `pai-ui` reads it through membership of group `pai`).
   Nothing else generates or injects a token, and the frontend never reads that file.
2. **The page receives it in the URL fragment**: `http://127.0.0.1:<port>/#token=<value>`. The value is visible ASCII with no
   spaces (a URL-safe token qualifies); percent-encoding is decoded. This is the only input the frontend supports.
3. **What puts it there does not exist yet.** The kiosk launcher is milestone M1.4b. Until then a developer adds the fragment by
   hand (see above). The mechanism is decided in M1.4b under one rule: the token must never appear in any process argument or
   environment, which every local account can read through `/proc`, nor in a URL passed on a command line. Candidates are a
   bootstrap page in a `0700` per-user directory that redirects to the app with the `#token=` fragment, or an `HttpOnly`
   `SameSite=Strict` cookie handshake. The cookie route would change this contract and `ApiClient` (the page would no longer hold
   the token at all); that is for M1.4b to decide, not decided here.
4. `main.tsx` calls `captureTokenFromUrl` once at startup, before React renders. It reads the value and calls
   `history.replaceState` in the same step, so the token leaves the address bar and the current history entry immediately. Other
   fragment parameters, the path and the query are left alone. A value that is not a usable token is removed too and treated
   as absent.
5. The token is kept **only in memory** by the page, in a private field of `ApiClient`. The page never writes it to
   `localStorage`, `sessionStorage`, cookies or IndexedDB, never puts it in a URL or query string, and never logs it; error
   messages never contain it. Because the field is private, `JSON.stringify`, `console.log` and React DevTools do not show it.
   This does not hide it from script running in the page (see the next section).
6. The client sends the token only to the origin that served the page: a path that resolves to another origin (`//host`,
   an absolute URL, `/\host`) is refused before any request is made.
7. No token at start: the status bar shows "Access token missing" and no request is sent. A `401`: "Access token rejected",
   and polling stops, because the same token will keep being refused.

Consequence: **a page reload loses the token**, because the fragment is already gone from the URL. Whatever supplies the fragment
must supply it again on every page load, for example after a browser crash or after a backend restart, which issues a new token.
This is the price of never storing the token; see [Known limits](#known-limits).

### What stripping does not remove

`history.replaceState` cleans the address bar and the history entry. The browser still keeps the URL the page was first loaded
with in its Navigation Timing entry (`performance.getEntriesByType('navigation')[0].name`) for as long as the page lives, and
the page cannot clear it. In Chromium, during verification, `location.href` was clean after startup while that entry still held
the `#token=` fragment. So script running in the page can read the token without going through `ApiClient`; it could equally
read the fragment before it is stripped, or wrap `fetch`. What limits who can run script in the page is the
Content-Security-Policy below (`script-src 'self'`, no inline script), the absence of third-party code, and the rule that nothing
is rendered as HTML from outside (the privacy test bans `dangerouslySetInnerHTML`). A handoff that never places the token in a
document URL, such as the cookie handshake named above, would remove this copy; M1.4b should weigh that.

## Offline-first, privacy and Content-Security-Policy

The UI makes no request to anything but its own origin: no CDN scripts, no web fonts from the internet (the typeface is bundled
in `dist/assets/`), no analytics, no telemetry. `tests/privacy-contract.test.ts` enforces this by reading the source: network
calls only in `services/api-client.ts`, no browser storage anywhere, no absolute or protocol-relative URL in script or CSS, no
style attributes or inline scripts. The test also feeds its own guards the leaks they exist to catch, so a guard that stops
catching them fails.

Recommended response headers for the backend to send with `dist/` (the same values are in `frontend/security-headers.ts` and
sent by `npm run preview`; a test fails if this document and that file disagree):

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

`default-src 'none'` with `'self'` added only where needed means the page can load its own script, style, font and images and
call its own origin, and nothing else. The build never inlines assets as `data:` URIs (`assetsInlineLimit: 0`), so `img-src`
needs no `data:`. There is no `unsafe-inline` and no `unsafe-eval`.

The backend should also serve `index.html` with `Cache-Control: no-cache` (assets are content-hashed and may be cached) and
should keep the Origin/Host checks from the [threat model](../security/THREAT_MODEL.md) (T9) in front of every route.

The typeface is Atkinson Hyperlegible Next (variable, Latin and Latin Extended subsets), from the npm package
`@fontsource-variable/atkinson-hyperlegible-next`, licensed under the SIL Open Font License 1.1. The licence text is shipped
at `dist/licenses/atkinson-hyperlegible-next-OFL.txt`. Other scripts fall back to the system fonts in the stack.

## Integration with the backend and the kiosk

Neither side below exists yet. The backend serves only `GET /health` today, and no kiosk launcher has been written.

What the backend must do when it serves the UI (the other half of M1.4):

- Serve `frontend/dist/` at `/` (the build uses relative asset URLs, so any mount works for the assets, but the API calls use
  root paths such as `/health`).
- Send the headers above, require the bearer token on API routes, and answer `GET /health` as described.
- Not require a token for the static files themselves, or the page could never load to receive it. Today every path, `/`
  included, is refused without a token (see [API_DOCUMENTATION](API_DOCUMENTATION.md)), so this needs an explicit exemption. The
  token travels in the URL fragment, which the browser never sends to the server.

What the kiosk launcher must do (milestone M1.4b):

- Start Chromium on `http://127.0.0.1:<port>/` and get the token to the page as the `#token=` fragment, by a mechanism that never
  puts the token in a process argument, an environment variable or a URL on a command line (see [Access token
  contract](#access-token-contract)). The token comes from the backend's token file; the launcher does not generate it, and the
  backend has no input for one. Do not put the token in the query string either: it would be sent to the server and end up in logs.
- Supply the token again on every page load: whenever it restarts the browser, and after a backend restart, which issues a new one.

## What the status bar means

| Backend state | Cause | Shown | Behaviour |
|---|---|---|---|
| `connecting` | first `/health` call in flight | "Backend connecting" | none |
| `connected` | valid `/health` reply | "Backend connected", "Version x.y.z" | re-checks every 15 s |
| `unreachable` | no connection, no reply within 5 s, an error status, a reply that fails validation, or the check itself failing unexpectedly (for example a page with no usable origin) | "Backend unreachable" and which of those happened | retries after 1 s, then 2, 4, 8, 16, 30 s (cap); the first success resets this |
| `unauthorized` | no token, or `401` | "Access token missing" / "Access token rejected" | stops polling |

The browser line reads "Browser reports online" or "Browser reports offline". It is what `navigator.onLine` says: that the
browser believes a network interface is up. It is not a connectivity test and not a statement about the backend; on this OS
outbound traffic is blocked by default, so "online" does not mean the internet is reachable. Each line is a polite live region
(`role="status"`), so a change is announced to screen readers without moving focus.

## Design and accessibility

- **Identity.** Quiet when healthy: ink on a pale mineral ground, with colour only for conditions that need attention. One
  typeface, chosen for legibility, set large and light for the empty-state heading. The header, conversation and status bar
  share one left edge.
- **Shape before colour.** Status marks differ in shape as well as colour: solid is present, ring is absent (not an error),
  dashed is in progress (it turns slowly, and stops under reduced motion), slashed is failed and retrying, barred is refused.
  The disabled message box also has a dashed outline, the same "waiting" cue.
- **Contrast.** `tests/tokens-contrast.test.ts` reads `src/styles/tokens.css` and checks, for light and dark, text >= 4.5:1
  and control outlines, status marks and the focus ring >= 3:1. Colour follows `prefers-color-scheme`; there is no manual switch.
- **Keyboard and focus.** Everything that can take focus shows a 2 px ring. Today nothing is interactive (the message box and
  Send are disabled, which is correct), so the only focusable thing is the conversation area when it scrolls, which Chromium
  makes keyboard-focusable.
- **Motion.** The only animation is the turning "connecting" mark, switched off by `prefers-reduced-motion`. A new animation
  must add its own reduced-motion rule beside it.
- **Size.** Designed for 1024x768 down to 800x600. On screens shorter than 44rem the vertical spacing tightens so the empty
  state fits without scrolling; below that the conversation area scrolls.

## Tests

`npm test` runs these (jsdom, Testing Library, fake timers where time matters):

| File | Guards |
|---|---|
| `services/token.test.ts` | Token captured and stripped from the URL; only the token removed; once only; malformed and encoded values; nothing stored. |
| `services/api-client.test.ts` | Authorization header sent; token never in a URL, option, console call, error or serialisation; no request without a token or to another origin; every error kind; timeout and cancellation, and a request that was already cancelled is never handed to the transport. |
| `services/health.test.ts` | `/health` guard accepts the contract and rejects malformed bodies; malformed replies fail as invalid. |
| `hooks/useBackendHealth.test.tsx` | State transitions, poll interval, backoff doubling and cap, reset on success, 401 stops polling, no-token, unmount cancels; a failure that is not an `ApiError` is shown as unreachable, logged and retried instead of ending polling. |
| `hooks/useBrowserOnline.test.tsx` | Follows the browser's online and offline events. |
| `components/StatusBar.test.tsx` | Every backend state and cause is worded truthfully; browser line is labelled as browser-reported; a change updates the same polite live regions in place and does not move focus. |
| `App.test.tsx` | The shell renders truthful states; "No model loaded" with reason; the empty state says the assistant is not available and promises no approval, storage or local-only guarantee; composer disabled with reason, linked to it, and unable to take focus; no navigation or invented controls; landmarks. |
| `tests/backend-proxy.test.ts` | The proxy default equals the backend's default address (read from `backend/core/config.py`) and the one written in `.env.example` and here; the loopback-only guard on `PAI_BACKEND_URL` (look-alike hosts, credentials in the URL, other schemes, the message never echoes the value); `build` ignores the variable and the dev and preview servers refuse a bad one; the test runner does not load the proxy settings. |
| `tests/package-contract.test.ts` | `engines` names no npm version; the lockfile records the same engines. |
| `tests/architecture.test.ts` | The layering above: each folder imports only the folders it may. |
| `tests/tokens-contrast.test.ts` | WCAG AA contrast of the tokens in both themes. |
| `tests/privacy-contract.test.ts` | Static privacy guards (network only in the API client, no storage, no absolute or protocol-relative URLs, no inline script or style), the guards' own detection of the leaks they exist for, the entry page, and the Content-Security-Policy (including that this document quotes it). |

jsdom has no layout or CSS engine, so visual quality, focus rings and responsive behaviour are checked by looking at the
built app in a browser, not by these tests.

## Verification record

Recorded at M1.4a, after the review fixes.

- **Node 20.18.1, npm 10.8.2 (Windows):** `npm run typecheck`, `npm test` (12 files, 209 tests), `npm run lint` and `npm run build`
  pass.
- **Debian 13 (trixie) toolchain, Node 20.19.2 with npm 9.2.0, in a throwaway container:** `npm ci`, `npm run typecheck`,
  `npm test` (209 tests), `npm run build` and `npm run lint` pass. Before the `engines` change the same `npm ci` stopped with
  `EBADENGINE`.
- **Real backend, default settings:** `npm run build`, then `npm run preview` with no `PAI_BACKEND_URL` in front of the real
  backend (`python -m backend` with scratch data and token paths, default port). Through the proxy, `GET /health` returned 200
  with the real token and 401 without. In Chromium at 1024x768, dark scheme, opened with `#token=`: the status bar read "Backend
  connected" with the version, the address bar was clean, web storage and cookies were empty, the message box was disabled, and
  the browser's Navigation Timing entry still held the `#token=` fragment (see [What stripping does not
  remove](#what-stripping-does-not-remove)).
- **Build size:** `index.html` 0.7 kB; JavaScript 233 kB (73 kB gzip); CSS 5.0 kB (1.8 kB gzip); two font files 34 kB and 19 kB
  (only the Latin file is downloaded for English text); about 300 kB in total.
- **Earlier, at the first build and before the empty-state wording changed:** the build was served under the strict policy in
  front of a stand-in backend and inspected at 1024x768 and 800x600 in light and dark; the page requested only its own origin and
  logged no console errors; connected, unreachable (error 503, then recovery) and token-rejected states were produced and
  checked. That visual pass was not repeated at 800x600 or in light mode after the wording change.
- **Not run:** the Chromium kiosk, serving by the backend, a screen reader.

## Known limits

- **No model, no chat.** The message box cannot be enabled: there is no model runtime and no backend endpoint for chat. Adding
  them replaces `features/model/modelStatus.ts` with real data and gives `Composer` a submit handler.
- **A reload loses the token** (see above). Whatever supplies the fragment must supply it on every page load.
- **The token is still readable by script in the page** through the browser's Navigation Timing entry for the first load (see
  [What stripping does not remove](#what-stripping-does-not-remove)). The fragment handoff cannot erase it; the handoff chosen in
  M1.4b decides whether this remains.
- **Only `/health` exists.** The UI calls nothing else; `BACKEND_PATHS` and the client grow with the backend.
- **English only.** Text is hard-coded; there is no translation layer. The bundled font covers Latin and Latin Extended; other
  scripts typed by a user render in a system font.
- **Dependency versions are bounded by Node 20.18.1.** Vite 7 and later and ESLint 10 need Node >= 20.19; Vitest 5 needs
  Node >= 22.12; `@testing-library/jest-dom` 7 needs Node >= 22. The pins are Vite 6.4.5, Vitest 4.1.12, jest-dom 6.9.1,
  and Biome 2.6.6 in place of ESLint (every ESLint 9 release is deprecated on npm, and ESLint 10 requires Node >= 20.19, which `engine-strict` refuses). jsdom
  is pinned to 26.1.0, the last release of the 26 line; its dependency `whatwg-encoding` prints a deprecation notice on install
  (development only, nothing from it ships). Revisit the pins when the image's Node is newer.
- **Development server is not CSP-strict** (hot reload needs inline script); use `npm run preview` to see production behaviour.
- **Not exercised yet:** the Chromium kiosk, serving by the backend, and assistive technology.
