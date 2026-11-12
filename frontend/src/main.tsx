import '@fontsource-variable/atkinson-hyperlegible-next/wght.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/base.css';
import { App } from './App';
import { ApiClient } from './services/api-client';

const container = document.getElementById('root');
if (container === null) {
  throw new Error('index.html is missing the #root element.');
}

createRoot(container).render(
  <StrictMode>
    <App client={new ApiClient()} />
  </StrictMode>,
);
