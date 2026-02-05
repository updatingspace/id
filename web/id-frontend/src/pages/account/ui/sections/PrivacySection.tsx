import React, { useEffect, useMemo, useState } from 'react';
import type { ConsentRow, Preferences, TimezoneRow } from '../../model/types';

type Props = {
  t: (k: string) => string;
  preferences?: Preferences;
  timezones: TimezoneRow[];
  consents: ConsentRow[];
  onSave: (payload: Preferences) => Promise<void>;
  onRevokeMarketing: () => Promise<void>;
};

export const PrivacySection: React.FC<Props> = ({
  t,
  preferences,
  timezones,
  consents,
  onSave,
  onRevokeMarketing,
}) => {
  const [prefs, setPrefs] = useState<Preferences>(preferences ?? {});
  const [busy, setBusy] = useState(false);

  useEffect(() => setPrefs(preferences ?? {}), [preferences]);

  const setScopePolicy = (scope: string, policy: 'allow' | 'ask' | 'deny') => {
    setPrefs((prev) => ({
      ...prev,
      privacy_scope_defaults: {
        ...(prev?.privacy_scope_defaults || {}),
        [scope]: policy,
      },
    }));
  };

  const scopes = useMemo(() => ['profile_basic', 'profile_extended', 'email', 'phone'] as const, []);

  const save = async () => {
    if (!prefs) return;
    setBusy(true);
    try {
      await onSave({
        language: prefs.language,
        timezone: prefs.timezone,
        marketing_opt_in: prefs.marketing_opt_in,
        privacy_scope_defaults: prefs.privacy_scope_defaults,
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <div className="card">
        <h3>{t('account.privacy')}</h3>

        <div className="form-grid">
          <label>
            <span>{t('preferences.language')}</span>
            <select
              value={prefs?.language || 'ru'}
              onChange={(e) => setPrefs({ ...prefs, language: e.target.value as 'ru' | 'en' })}
            >
              <option value="ru">Русский</option>
              <option value="en">English</option>
            </select>
          </label>

          <label>
            <span>{t('preferences.timezone')}</span>
            <select
              value={prefs?.timezone || ''}
              onChange={(e) => setPrefs({ ...prefs, timezone: e.target.value })}
            >
              <option value="">{t('preferences.timezone.notSelected')}</option>
              {timezones.map((tz) => (
                <option key={tz.name} value={tz.name}>
                  {tz.display_name}
                </option>
              ))}
            </select>
          </label>

          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={!!prefs?.marketing_opt_in}
              onChange={(e) => setPrefs({ ...prefs, marketing_opt_in: e.target.checked })}
            />
            <span>{t('preferences.marketing')}</span>
          </label>
        </div>

        <div className="scope-grid">
          {scopes.map((scope) => {
            const currentPolicy = prefs?.privacy_scope_defaults?.[scope] || 'ask';
            return (
              <div key={scope} className="scope-policy">
                <strong>{scope}</strong>
                <div className="pill-row">
                  {(['allow', 'ask', 'deny'] as const).map((policy) => (
                    <button
                      key={policy}
                      type="button"
                      className={`mini-pill ${currentPolicy === policy ? 'active' : ''}`}
                      onClick={() => setScopePolicy(scope, policy)}
                    >
                      {policy}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <button className="primary-button" onClick={save} disabled={busy}>
          {t('preferences.save')}
        </button>
      </div>

      <div className="card">
        <h3>Согласия</h3>
        <div className="list">
          {consents.map((consent) => (
            <div key={`${consent.kind}-${consent.granted_at}`} className="list-row">
              <div>
                <strong>{consent.kind}</strong>
                <span className="muted">{consent.granted_at}</span>
              </div>

              {consent.revoked_at ? (
                <span className="muted">Отозвано</span>
              ) : consent.kind === 'marketing' ? (
                <button className="ghost-button" onClick={onRevokeMarketing}>
                  Отозвать
                </button>
              ) : null}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
