import React, { useState } from 'react';

type Props = {
  t: (k: string) => string;
  requiresMfa: boolean;

  onExport: (payload: { password: string; mfa_code?: string }) => Promise<any>;
  onDelete: (payload: { password: string; mfa_code?: string; reason: string }) => Promise<any>;

  onDone: () => void;
  setError: (v: string | null) => void;
};

export const DataSection: React.FC<Props> = ({
  t,
  requiresMfa,
  onExport,
  onDelete,
  onDone,
  setError,
}) => {
  const [reauthForm, setReauthForm] = useState({ password: '', mfa_code: '' });
  const [busy, setBusy] = useState<{ export?: boolean; delete?: boolean }>({});

  const exportData = async () => {
    setError(null);
    if (!reauthForm.password.trim()) return;

    setBusy((p) => ({ ...p, export: true }));
    try {
      const payload = await onExport({
        password: reauthForm.password,
        mfa_code: requiresMfa ? reauthForm.mfa_code || undefined : undefined,
      });

      const blob = new Blob([JSON.stringify(payload.payload ?? payload, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'id-data.json';
      link.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err?.message || 'Не удалось экспортировать данные');
    } finally {
      setBusy((p) => ({ ...p, export: false }));
    }
  };

  const deleteAccount = async () => {
    setError(null);
    if (!reauthForm.password.trim()) return;
    if (!window.confirm('Удалить аккаунт без возможности восстановления?')) return;

    setBusy((p) => ({ ...p, delete: true }));
    try {
      await onDelete({
        password: reauthForm.password,
        mfa_code: requiresMfa ? reauthForm.mfa_code || undefined : undefined,
        reason: 'user_request',
      });
      onDone();
    } catch (err: any) {
      setError(err?.message || 'Не удалось удалить аккаунт');
    } finally {
      setBusy((p) => ({ ...p, delete: false }));
    }
  };

  return (
    <div className="stack">
      <div className="card">
        <h3>{t('data.export')}</h3>
        <p className="muted">{t('data.reauthDescription')}</p>

        <div className="form-row">
          <label>
            <span>{t('security.currentPassword')}</span>
            <input
              type="password"
              value={reauthForm.password}
              onChange={(e) => setReauthForm({ ...reauthForm, password: e.target.value })}
            />
          </label>

          {requiresMfa && (
            <label>
              <span>{t('login.mfa')}</span>
              <input
                value={reauthForm.mfa_code}
                onChange={(e) => setReauthForm({ ...reauthForm, mfa_code: e.target.value })}
              />
            </label>
          )}
        </div>

        <button className="primary-button" onClick={exportData} disabled={!!busy.export || !reauthForm.password.trim()}>
          {t('data.exportButton')}
        </button>
      </div>

      <div className="card danger">
        <h3>{t('data.delete')}</h3>
        <p className="muted">Удаление необратимо, все сессии будут отозваны.</p>

        <button className="danger-button" onClick={deleteAccount} disabled={!!busy.delete || !reauthForm.password.trim()}>
          {t('data.deleteButton')}
        </button>
      </div>
    </div>
  );
};
