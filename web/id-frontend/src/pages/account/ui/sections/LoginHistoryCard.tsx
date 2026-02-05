import React from 'react';

type Props = {
  events: any[]; // [{ created_at, status, ip_address }]
};

export const LoginHistoryCard: React.FC<Props> = ({ events }) => {
  if (!events || events.length === 0) return null;

  return (
    <div className="card">
      <h3>История входов</h3>
      <div className="list">
        {events.map((item: any, idx: number) => (
          <div key={`${item.created_at}-${idx}`} className="list-row">
            <div>
              <strong>{item.status === 'success' ? 'Успешный вход' : 'Ошибка входа'}</strong>
              <span className="muted">{item.created_at}</span>
            </div>
            <span className="muted">{item.ip_address || '—'}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
