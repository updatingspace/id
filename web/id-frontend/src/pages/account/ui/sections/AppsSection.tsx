import React, { useState } from 'react';
import { ErrorBanner } from '../banners';
import type { OAuthAppRow } from '../../model/types';

type Props = {
  t: (k: string) => string;
  apps: OAuthAppRow[];
  onRevoke: (clientId: string) => Promise<void>;
};

export const AppsSection: React.FC<Props> = ({ t, apps, onRevoke }) => {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<{ [k: string]: boolean }>({});

  const revoke = async (clientId: string) => {
    setError(null);
    setBusy((p) => ({ ...p, [clientId]: true }));
    try {
      await onRevoke(clientId);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('error.SERVER_ERROR'));
    } finally {
      setBusy((p) => ({ ...p, [clientId]: false }));
    }
  };

  return (
    <div className="card">
      {error && <ErrorBanner message={error} />}
      <h3>{t('apps.title')}</h3>

      <div className="list">
        {apps.map((app) => (
          <div key={app.client_id} className="list-row">
            <div>
              <strong>{app.name}</strong>
              <span className="muted">{(app.scopes || []).join(', ')}</span>
            </div>

            <button
              className="ghost-button"
              onClick={() => revoke(app.client_id)}
              disabled={!!busy[app.client_id]}
            >
              {t('apps.revoke')}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
