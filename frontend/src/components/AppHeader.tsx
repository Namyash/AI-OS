import './AppHeader.css';
import { StateMark } from './StateMark';

interface AppHeaderProps {
  /** Short model state, for example "No model loaded". */
  modelLabel: string;
  /** Why the model is in that state, in plain words. */
  modelReason: string;
}

/** Product name on the left, truthful model state on the right. Nothing here is interactive. */
export function AppHeader({ modelLabel, modelReason }: AppHeaderProps) {
  return (
    <header className="app-header">
      <div className="app-header__inner">
        <h1 className="app-header__title">Private AI OS</h1>
        <div className="model-indicator">
          <p className="model-indicator__state">
            <StateMark kind="ring" />
            {modelLabel}
          </p>
          <p className="model-indicator__reason">{modelReason}</p>
        </div>
      </div>
    </header>
  );
}
