# Frontend

Status: milestone M1.4b, frontend part. The application builds, is tested, and has been run in Chromium through the
`npm run preview` proxy against the real backend (see [Verification record](#verification-record)). The page holds no
credential: the kiosk launcher signs the window in with a session cookie, as specified in
[KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md). Serving of the UI by the backend, the launcher and the
cookie have not been exercised together with this build; what is and is not verified is listed below. Nothing here
changes what [DEVELOPMENT_STATUS.md](../../DEVELOPMENT_STATUS.md) says works end to end.

## What it is

A React + TypeScript single-page app in `frontend/`. The backend serves `frontend/dist/` from the site root behind the
same session check as its API, and Chromium runs it full-screen in a kiosk (see [ARCHITECTURE](../architecture/ARCHITECTURE.md)
§3 and [KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md)). It shows only what is backed by real data:

| Area | What is real | What is deliberately absent |
|---|---|---|
| Header | Product name. Model indicator: "No model loaded" with the reason. | Model picker, settings, account menu. |
| Conversation | An empty state saying the assistant is not available yet and why; a message box that is **disabled** with its reason beside it. | Messages, history, sending. The model runtime starts in Phase 2. Any statement about approvals, where data lives or what runs where: those appear with the features that make them true. |
| Status bar | Backend state from `GET /health`; the browser's own online/offline report, labelled as such. | Anything the backend cannot tell us yet. |
| Navigation | None. | Memory, files, tasks and settings screens: they appear with the features behind them. |

## Setup

Requires Node >= 20.18.1 (developed on 20.18.1). There is no npm minimum: use the npm that comes with your Node. Debian 13,
the base of the image, packages Node 20 with npm 9, and `npm ci`, the tests and the build were run on that pair at M1.4a (see
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
| `npm run dev` | Vite dev server on `127.0.0.1:5173` with hot reload; forwards backend paths to the backend, and can sign in with a developer token file (below). |
| `npm run build` | `typecheck`, then `vite build` into `dist/`. Does not read the proxy or token-file settings. |
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

The variable is read by the build tooling only and is never placed in the browser bundle. It must point at this computer
(`127.0.0.1`, `localhost` or `[::1]`) because the proxy can attach your token to the requests it forwards: anything else makes
the dev and preview servers refuse to start. `npm run build` and `npm test` do not use the proxy and ignore the variable. Add a
path to `BACKEND_PATHS` when the backend gains an endpoint the UI uses. The dev server relaxes nothing in the app, but Vite's
hot-reload client needs inline script, so the strict policy below is applied by `npm run preview`, not `npm run dev`.

### Signing in during development

In the kiosk the launcher installs the session cookie (see [Session contract](#session-contract)). A plain browser tab on the
dev server has no such cookie, so by default the backend answers `/health` with `401` and the status bar says "No valid
session". To sign a dev tab in, give the dev or preview server the file that holds a backend token:

```bash
# terminal 1, from the repository root: the real backend. The token file is replaced at every start.
PAI_DATA_DIR=/abs/path/pai-data PAI_TOKEN_FILE=/abs/path/pai-token python -m backend

# terminal 2: the same file, named for the dev server
cd frontend && PAI_DEV_TOKEN_FILE=/abs/path/pai-token npm run dev
```

The defaults for `PAI_TOKEN_FILE` and `PAI_DATA_DIR` are the image's Linux paths, so on a development machine point both at
folders you own, as absolute paths. Then open `http://127.0.0.1:5173/`; no fragment, no query.

- **What it does.** For every forwarded request the dev or preview proxy reads the file and adds `Authorization: Bearer <token>`
  between the dev server and the backend. The browser never sees the token: its own request carries no such header and the
  answer carries none.
- **The variable holds a path, never the token.** The path is not secret and may sit in the shell or in `frontend/.env`; the
  token must never be placed on a command line or in an environment variable, where every local account can read it. The path
  must be absolute, like the backend's own `PAI_TOKEN_FILE`; a relative one stops the servers from starting.
- **Read for every request.** The backend issues a new token at each start; after a restart the next request uses the new
  one without restarting the dev server. Whitespace around the token (the newline an editor adds) is ignored.
- **A file that cannot be used** (missing, empty, or holding anything but one token of visible characters on one line, which
  also keeps a stray line break from becoming part of a header) is not an error that stops anything: the request is
  forwarded without the header, so the page shows "No valid session", and the dev server prints one warning that names the
  variable and the kind of problem, never the path or the content. The warning is printed again if the file works in between.
- **Loopback only.** The header is added only when the target is on this computer (see above). A target that is not makes the
  servers refuse to start before the token file is read.
- **Never in the build.** `npm run build` does not read the variable, and nothing under `src/` imports the tooling that does.
  `tests/production-bundle.test.ts` builds the project for real with the variables set and fails if the output contains the
  variable names, the path, the token or any `Authorization` text.

## Structure

```
frontend/
  index.html               entry page: no inline script, no external resource
  backend-proxy.ts         dev/preview proxy: target, its default, the loopback-only guard, the optional dev token header
  security-headers.ts      the Content-Security-Policy and headers (single source; see below)
  vite.config.ts           build, dev/preview servers and proxy
  vitest.config.ts         test runner configuration (kept apart so tests never load the proxy settings)
  biome.json               lint and format rules
  public/                  favicon and the font licence, copied into dist/
  src/
    main.tsx               startup: create client, render
    App.tsx                the shell: header, conversation, status bar
    services/              the only place the UI performs I/O
      api-client.ts        same-origin GET with timeout, typed errors; no credential
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
  tests/                   checks that read files or run the tooling: privacy contract, layering, proxy and token file, production bundle, package contract, colour contrast
    support/               helpers that read and scan the source
```

Dependencies point one way, and `tests/architecture.test.ts` fails when they do not: `services` import only `services`; `hooks` import
`hooks` and `services`; `components` import `components` and `hooks` (a component receives plain props and never imports a
feature); `features` import `features`, `components`, `hooks` and `services`. `App.tsx` and `main.tsx` sit above all of them.
Nothing under `src/` imports anything outside `src/`, so the build tooling (the proxy and its token-file settings) cannot reach the bundle.

## Backend contract the UI relies on

Only this, nothing more:

- The window is signed in by a session cookie, `pai_session`, installed by the kiosk launcher: HttpOnly, SameSite=Strict, host-only on
  the backend's origin. The UI neither sets, reads nor sends it explicitly; the browser attaches it to same-origin requests.
- `GET /health` returns `{"status":"ok","schema_version":<integer>,"version":"<string>"}`. Extra fields are ignored. The
  version string must be 1 to 64 characters because it is displayed.
- Errors have the uniform shape `{"error":{"code":"...","message":"..."}}`. The UI uses the HTTP status to decide what a failure
  means and keeps `code` for diagnostics; a body that is not this shape does not change the outcome.
- `401` (code `unauthorized`) means this window has no valid session.

The reply is checked at run time by the hand-written guard `isHealthResponse` (`services/health.ts`) because it comes from
outside the page. A reply that fails the check is treated as a failure (`unreachable`, cause "unexpected reply"), never as
"connected". Requests use `GET` only, with `credentials: 'same-origin'`, `cache: 'no-store'`, `referrerPolicy: 'no-referrer'`
and `redirect: 'error'`. A redirect is therefore an error, so `/health` must be served at exactly that path.

## Session contract

1. **The page holds no secret.** The kiosk launcher, running as the kiosk user, reads the backend's token file, exchanges the
   token for a session id (`POST /v1/session`), installs it as the `pai_session` cookie over the browser's DevTools pipe and only
   then navigates to the plain endpoint URL. The URL has no fragment and no query, and no command-line argument, environment
   variable or document URL ever carries a secret (see [KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md)).
2. **The UI takes no part.** It has no code that reads a token, sets an `Authorization` header, reads the URL fragment or query
   string, or touches cookies and web storage; `tests/privacy-contract.test.ts` fails when any of these appears in `src/`, and
   `api-client.test.ts` fails if a request carries an `Authorization` header or anything but `credentials: 'same-origin'`.
3. **The client calls its own origin only.** A path that resolves to another origin (`//host`, an absolute URL, `/\host`) is
   refused before any request is made. The cookie is host-only and SameSite=Strict, so it would not travel to another site
   anyway, and the Content-Security-Policy below allows `connect-src 'self'` only.
4. **A `401` is "no valid session", not a retry.** It means the window never had a session, it has expired (absolute lifetime), or
   the backend restarted, which invalidates every session. The page cannot create one, so the status bar says so (see
   [What the status bar means](#what-the-status-bar-means)) and polling stops. Reloading the page does not help by itself; only
   whatever installs the cookie can restore it, which on the kiosk means restarting the session.

What this does not do: HttpOnly keeps the session id out of reach of script in the page, but script in the page can still make
same-origin requests that carry the cookie. What limits who can run script in the page is the Content-Security-Policy below
(`script-src 'self'`, no inline script), the absence of third-party code, and the rule that nothing is rendered as HTML from outside
(the privacy test bans `dangerouslySetInnerHTML`). On the backend side, a cookie-authenticated request that is not `GET`, `HEAD` or
`OPTIONS` must carry an `Origin` equal to its own origin.

## Offline-first, privacy and Content-Security-Policy

The UI makes no request to anything but its own origin: no CDN scripts, no web fonts from the internet (the typeface is bundled
in `dist/assets/`), no analytics, no telemetry. `tests/privacy-contract.test.ts` enforces this by reading the source: network
calls only in `services/api-client.ts`, no browser storage anywhere, no credential handling, no absolute or protocol-relative URL
in script or CSS, no style attributes or inline scripts. The test also feeds its own guards the leaks they exist to catch, so a
guard that stops catching them fails.

**What the backend sends.** The backend serves `dist/` with the static headers fixed in
[KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md) (Static UI): the policy below, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and `Cache-Control: no-store` for HTML (assets are content-hashed). The UI needs nothing beyond
that policy: it loads its own script, style, font and images, calls its own origin, and has no inline script or style, no
`eval` and no `data:` URI (the build never inlines assets: `assetsInlineLimit: 0`).

**One policy, two copies.** The policy is `frontend/security-headers.ts` (applied by `npm run preview` so the built bundle is
exercised under it) and `backend/api/static.py` (what the service sends). `tests/security/test_csp_contract.py` fails if they differ,
and a frontend test fails if this document and the TypeScript file disagree:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

`default-src 'none'` with `'self'` added only where needed means the page can load its own script, style, font and images and
call its own origin, and nothing else (no frames, workers or objects). There is no `unsafe-inline` and no `unsafe-eval`. The
backend keeps the Origin/Host checks from the [threat model](../security/THREAT_MODEL.md) (T9) in front of every route, static
files included.

The typeface is Atkinson Hyperlegible Next (variable, Latin and Latin Extended subsets), from the npm package
`@fontsource-variable/atkinson-hyperlegible-next`, licensed under the SIL Open Font License 1.1. The licence text is shipped
at `dist/licenses/atkinson-hyperlegible-next-OFL.txt`. Other scripts fall back to the system fonts in the stack.

## Integration with the backend and the kiosk

The contract for both sides is [KIOSK_SESSION_DESIGN](../architecture/KIOSK_SESSION_DESIGN.md); this is what the UI needs from them.

- **Backend:** serve `frontend/dist/` at `/` (the build uses relative asset URLs, so any mount works for the assets, but the API
  calls use root paths such as `/health`), behind the same guard as the API, so the shell itself needs the cookie and there is
  no unauthenticated route; answer `GET /health` as described; reply `401` with the uniform error body when there is no valid
  session. The UI needs no exemption for its static files.
- **Kiosk launcher:** install the `pai_session` cookie before navigating to the plain endpoint URL, and install it again (a new
  session) whenever it restarts the browser or the backend has restarted. The UI does nothing to recover on its own: after a
  `401` it waits for the session to be restored.

## What the status bar means

| Backend state | Cause | Shown | Behaviour |
|---|---|---|---|
| `connecting` | first `/health` call in flight | "Backend connecting" | none |
| `connected` | valid `/health` reply | "Backend connected", "Version x.y.z" | re-checks every 15 s |
| `unreachable` | no connection, no reply within 5 s, an error status other than 401, a reply that fails validation, or the check itself failing unexpectedly (for example a page with no usable origin) | "Backend unreachable" and which of those happened | retries after 1 s, then 2, 4, 8, 16, 30 s (cap); the first success resets this |
| `unauthorized` | `401` | "No valid session", then "This window has no valid session with the assistant service. Restarting the session restores it." | stops polling |

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

`npm test` runs these (jsdom, Testing Library, fake timers where time matters; the files under `tests/` that run the tooling use
the node environment):

| File | Guards |
|---|---|
| `services/api-client.test.ts` | Plain same-origin GET with `credentials: 'same-origin'` and no `Authorization` header or URL secret; no cache, no referrer, no redirects; no request to another origin; 401 maps to `unauthorized` with its own wording (no token, URL or backend text); every other error kind; timeout and cancellation, and a request that was already cancelled is never handed to the transport. |
| `services/health.test.ts` | `/health` guard accepts the contract and rejects malformed bodies; malformed replies fail as invalid. |
| `hooks/useBackendHealth.test.tsx` | State transitions, poll interval, backoff doubling and cap, reset on success, 401 stops polling (also after it was connected, as after a backend restart) while a 403 is retried, unmount cancels; a failure that is not an `ApiError` is shown as unreachable, logged and retried instead of ending polling. |
| `hooks/useBrowserOnline.test.tsx` | Follows the browser's online and offline events. |
| `components/StatusBar.test.tsx` | Every backend state and cause is worded truthfully; the no-session copy names the problem and the way back and mentions no token, URL or address, and is not shown as retrying; browser line is labelled as browser-reported; a change updates the same polite live regions in place and does not move focus. |
| `App.test.tsx` | The shell renders truthful states, including "No valid session" on a 401; "No model loaded" with reason; the empty state says the assistant is not available and promises no approval, storage or local-only guarantee; composer disabled with reason, linked to it, and unable to take focus; no navigation or invented controls; landmarks. |
| `tests/backend-proxy.test.ts` | The proxy default equals the backend's default address (read from `backend/core/config.py`) and the one written in `.env.example` and here; the loopback-only guard on `PAI_BACKEND_URL` (look-alike hosts, credentials in the URL, other schemes, the message never echoes the value); the dev token file: read, trimmed, re-read for every request, missing, empty and malformed files send no header and warn once without echoing content, a relative path and a non-loopback target are refused before anything can be injected; `build` ignores the variables and the dev and preview servers share one proxy; the test runner does not load the proxy settings. |
| `tests/dev-proxy.test.ts` | The real `vite.config.ts` dev server in front of a stand-in backend: the header reaches the backend and not the page, a replaced token file is picked up without a restart, a missing file or no variable forwards the request without a header. |
| `tests/production-bundle.test.ts` | A real production build with the dev variables set to marker values: no variable name, path, token, proxy target, `Authorization` or `Bearer` text in any output file. |
| `tests/package-contract.test.ts` | `engines` names no npm version; the lockfile records the same engines. |
| `tests/architecture.test.ts` | The layering above: each folder imports only the folders it may; nothing under `src/` imports from outside `src/`. |
| `tests/tokens-contrast.test.ts` | WCAG AA contrast of the tokens in both themes. |
| `tests/privacy-contract.test.ts` | Static privacy guards (network only in the API client, no storage, no credential handling, no absolute or protocol-relative URLs, no inline script or style), the guards' own detection of the leaks they exist for, the entry page, and the Content-Security-Policy (including that this document quotes it). |

jsdom has no layout or CSS engine, so visual quality, focus rings and responsive behaviour are checked by looking at the
built app in a browser, not by these tests.

## Verification record

Recorded at M1.4b (frontend part), on Node 20.18.1 with npm 10.8.2 (Windows).

- **Checks:** `npm run typecheck`, `npm test` (13 files, 249 tests), `npm run lint`, `npm run build` and `npm audit` (0
  vulnerabilities) pass. Mutation check, in a scratch copy: 31 deliberate breaks of the token-file, session and privacy code
  (the loopback check removed, the header named wrongly, the file read once, `credentials` changed, the 401 mapping or its
  copy changed, the dev settings imported into the app or baked in at build time, a request outside the client, and others)
  each made the suite fail.
- **Real backend, through the dev proxy header:** the backend as committed before the session endpoints were added (bearer
  token only), started from a scratch export with scratch data and token paths on the default port; `npm run build`, then
  `npm run preview` with `PAI_DEV_TOKEN_FILE` naming the token file. `GET /health` through the proxy returned 200. In Chromium
  the status bar read "Backend connected" with the version, the URL had no fragment or query, cookies and web storage were
  empty, and the page requested only its own origin. Without `PAI_DEV_TOKEN_FILE` the proxy returned 401 and the status bar read "No valid
  session" with the explanation, a barred mark and no retries (one `/health` request). At 800x600 and 1024x768 the longer
  message wraps inside the bar without overflow (measured; the screenshots of an emulated size were cropped by the pane).
- **Build size:** `index.html` 0.7 kB; JavaScript 232 kB (73 kB gzip); CSS 5.0 kB (1.8 kB gzip); two font files 34 kB and 19 kB
  (only the Latin file is downloaded for English text); about 300 kB in total. The built script no longer contains the word
  "Authorization".
- **Debian 13 (trixie) toolchain, Node 20.19.2 with npm 9.2.0, in a throwaway container, at M1.4a (209 tests then):** `npm ci`,
  typecheck, tests, build and lint passed; before the `engines` change the same `npm ci` stopped with `EBADENGINE`. Not repeated
  at M1.4b.
- **Not run:** the UI served by the backend, the launcher installing the cookie, the Chromium kiosk, the strict policy against the
  backend's own headers, a screen reader.

## Known limits

- **No model, no chat.** The message box cannot be enabled: there is no model runtime and no backend endpoint for chat. Adding
  them replaces `features/model/modelStatus.ts` with real data and gives `Composer` a submit handler.
- **A lost session is not recovered by the page.** After a `401` the page stops polling and shows "No valid session"; it
  continues only after whatever installs the cookie has done so and the page is loaded again. A backend restart ends every
  session, so on the kiosk the launcher must start a new one.
- **The cookie is ambient authority inside the page.** HttpOnly hides the session id from script but not from the requests
  script can make (see [Session contract](#session-contract)); the Content-Security-Policy and the absence of third-party code
  are what limit that.
- **Development token file.** `PAI_DEV_TOKEN_FILE` gives the dev and preview proxies the same power as the token to anyone
  who can reach those servers; they listen on `127.0.0.1` only and refuse a non-loopback backend, so this is limited to local accounts that can open that port.
- **Only `/health` exists.** The UI calls nothing else; `BACKEND_PATHS` and the client grow with the backend.
- **English only.** Text is hard-coded; there is no translation layer. The bundled font covers Latin and Latin Extended; other
  scripts typed by a user render in a system font.
- **Dependency versions are bounded by Node 20.18.1.** Vite 7 and later and ESLint 10 need Node >= 20.19; Vitest 5 needs
  Node >= 22.12; `@testing-library/jest-dom` 7 needs Node >= 22. The pins are Vite 6.4.5, Vitest 4.1.12, jest-dom 6.9.1,
  and Biome 2.6.6 in place of ESLint (every ESLint 9 release is deprecated on npm, and ESLint 10 requires Node >= 20.19, which `engine-strict` refuses). jsdom
  is pinned to 26.1.0, the last release of the 26 line; its dependency `whatwg-encoding` prints a deprecation notice on install
  (development only, nothing from it ships). Revisit the pins when the image's Node is newer.
- **Development server is not CSP-strict** (hot reload needs inline script); use `npm run preview` to see production behaviour.
- **Not exercised yet:** the Chromium kiosk, serving by the backend with cookie authentication, and assistive technology.
