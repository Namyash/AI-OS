# components

Presentational React components shared across the shell: `AppHeader` (product name and model indicator),
`StatusBar` (backend and browser connection state) and `StateMark` (the status glyph whose shape, not colour,
carries the meaning). They receive plain props and perform no I/O. They import only from `components/` and `hooks/`, never
from `features/`; `tests/architecture.test.ts` enforces it.
