import './App.css';
import { AppHeader } from './components/AppHeader';
import { StatusBar } from './components/StatusBar';
import { ConversationView } from './features/conversation/ConversationView';
import { NO_MODEL } from './features/model/modelStatus';
import { useBackendHealth } from './hooks/useBackendHealth';
import { useBrowserOnline } from './hooks/useBrowserOnline';
import type { ApiClient } from './services/api-client';

/**
 * Full-screen shell: header, conversation (the primary surface) and a status bar.
 * It only shows what is backed by real data; features that do not exist yet have no controls here.
 */
export function App({ client }: { client: ApiClient }) {
  const backend = useBackendHealth(client);
  const browserOnline = useBrowserOnline();

  return (
    <div className="app-shell">
      <AppHeader modelLabel={NO_MODEL.label} modelReason={NO_MODEL.reason} />
      <ConversationView model={NO_MODEL} />
      <StatusBar backend={backend} browserOnline={browserOnline} />
    </div>
  );
}
