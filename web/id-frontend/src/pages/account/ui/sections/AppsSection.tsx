import React, { useState } from 'react';

type Props = {
  t: (k: string) => string;
  apps: any[]; // [{ client_id, name, scopes }]
  onRevoke: (clientId: string) => Promise<void>;
};

export const AppsSection: React.FC<Props> = ({ t, apps, onRevoke }) => {
  const [busy, setBusy] = useState<{ [k: string]: boolean }>({});

  const revoke = async (clientId: string) => {
    setBusy((p) => ({ ...p, [clientId]: true }));
    try {
      await onRevoke(clientId);
    } finally {
      setBusy((p) => ({ ...p, [clientId]: false }));
    }
  };

  return (
    <div className="card">
      <h3>{t('apps.title')}</h3>

      <div className="list">
        {apps.map((app: any) => (
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
