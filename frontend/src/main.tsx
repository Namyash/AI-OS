import '@fontsource-variable/atkinson-hyperlegible-next/wght.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/base.css';
import { App } from './App';
import { ApiClient } from './services/api-client';
import { captureTokenFromUrl } from './services/token';

const container = document.getElementById('root');
if (container === null) {
  throw new Error('index.html is missing the #root element.');
}

// Once, before anything renders: this removes the token from the address bar. It stays in the client's memory only.
const client = new ApiClient({ token: captureTokenFromUrl(window.location, window.history) });

createRoot(container).render(
  <StrictMode>
    <App client={client} />
  </StrictMode>,
);
