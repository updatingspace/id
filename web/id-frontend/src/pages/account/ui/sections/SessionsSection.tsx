import React, { useState } from 'react';
import type { SessionRow } from '../../model/types';

type Props = {
  t: (k: string) => string;
  sessions: SessionRow[];
  onRevokeSession: (id: string) => Promise<void>;
  onRevokeAll: () => Promise<void>;
};

export const SessionsSection: React.FC<Props> = ({ t, sessions, onRevokeSession, onRevokeAll }) => {
  const [busy, setBusy] = useState<{ [k: string]: boolean }>({});

  const safe = async (key: string, fn: () => Promise<void>) => {
    setBusy((p) => ({ ...p, [key]: true }));
    try {
      await fn();
    } finally {
      setBusy((p) => ({ ...p, [key]: false }));
    }
  };

  return (
    <div className="card">
      <h3>{t('sessions.title')}</h3>

      <div className="list">
        {sessions.map((session) => (
          <div key={session.id} className="list-row">
            <div>
              <strong>{session.user_agent || 'Unknown device'}</strong>
              <span className="muted">{session.ip || '—'}</span>
            </div>

            {!session.current && (
              <button
                className="ghost-button"
                onClick={() => safe(`revoke:${session.id}`, () => onRevokeSession(session.id))}
                disabled={!!busy[`revoke:${session.id}`]}
              >
                Завершить
              </button>
            )}
          </div>
        ))}
      </div>

      <button className="secondary-button" onClick={() => safe('revokeAll', onRevokeAll)} disabled={!!busy.revokeAll}>
        {t('sessions.revokeAll')}
      </button>
    </div>
  );
};
