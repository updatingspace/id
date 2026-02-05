import React, { useMemo, useState } from 'react';

type Props = {
  t: (k: string) => string;
  user: any;
  emailVerified: boolean;

  mfaStatus: any; // { has_totp, has_webauthn, has_recovery_codes, ... }
  passkeys: any[]; // [{ id, name, is_passwordless, ... }]
  providers: Array<{ id: string; name: string }>;
  requiresMfa: boolean;

  onChangePassword: (current: string, next: string) => Promise<void>;

  onEnableTotp: () => Promise<any>; // totpBegin -> { svg_data_uri, ... }
  onConfirmTotp: (code: string) => Promise<any>; // totpConfirm -> { recovery_codes? }
  onDisableTotp: () => Promise<any>;

  onRegenRecovery: () => Promise<{ recovery_codes: string[] }>;

  onAddPasskey: () => Promise<void>;
  onDeletePasskey: (id: string) => Promise<void>;

  onLinkProvider: (providerId: string) => Promise<any>; // getOAuthLinkUrl(providerId, '/account') -> { authorize_url, method }
  onUnlinkProvider: (providerId: string) => Promise<void>;

  setMessage: (v: string | null) => void;
  setError: (v: string | null) => void;
};

export const SecuritySection: React.FC<Props> = ({
  t,
  user,
  emailVerified,
  mfaStatus,
  passkeys,
  providers,
  requiresMfa,
  onChangePassword,
  onEnableTotp,
  onConfirmTotp,
  onDisableTotp,
  onRegenRecovery,
  onAddPasskey,
  onDeletePasskey,
  onLinkProvider,
  onUnlinkProvider,
  setMessage,
  setError,
}) => {
  const [passwordForm, setPasswordForm] = useState({ current: '', next: '' });

  const [totpSetup, setTotpSetup] = useState<any | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [busy, setBusy] = useState<{ [k: string]: boolean }>({});

  const linkedProviders = useMemo(() => new Set(user?.oauth_providers || []), [user?.oauth_providers]);

  const safe = async (key: string, fn: () => Promise<void>) => {
    setBusy((p) => ({ ...p, [key]: true }));
    try {
      await fn();
    } finally {
      setBusy((p) => ({ ...p, [key]: false }));
    }
  };

  const submitPassword = async () => {
    setMessage(null);
    setError(null);
    await safe('pwd', async () => {
      await onChangePassword(passwordForm.current, passwordForm.next);
      setPasswordForm({ current: '', next: '' });
    });
  };

  const beginTotp = async () => {
    setMessage(null);
    setError(null);
    await safe('totpBegin', async () => {
      try {
        const begin = await onEnableTotp();
        setTotpSetup(begin);
      } catch (err: any) {
        if (err?.code === 'EMAIL_VERIFICATION_REQUIRED') {
          setError(t('security.totp.emailVerificationRequired'));
        } else {
          setError(err?.message || 'Не удалось начать настройку 2FA');
        }
      }
    });
  };

  const confirmTotp = async () => {
    if (!totpCode.trim()) return;
    setMessage(null);
    setError(null);
    await safe('totpConfirm', async () => {
      try {
        const res = await onConfirmTotp(totpCode.trim());
        if (res?.recovery_codes?.length) {
          window.alert(`Сохраните резервные коды:\n${res.recovery_codes.join('\n')}`);
        }
        setTotpSetup(null);
        setTotpCode('');
        setMessage('2FA включена');
      } catch (err: any) {
        if (err?.code === 'TOTP_SETUP_REQUIRED') {
          setTotpSetup(null);
          setTotpCode('');
          setError('Начните настройку 2FA заново');
        } else {
          setError(err?.message || 'Не удалось подтвердить 2FA');
        }
      }
    });
  };

  const disableTotp = async () => {
    setMessage(null);
    setError(null);
    await safe('totpDisable', async () => {
      await onDisableTotp();
      setMessage('2FA отключена');
    });
  };

  const regenRecovery = async () => {
    setMessage(null);
    setError(null);
    await safe('regen', async () => {
      const regen = await onRegenRecovery();
      window.alert(`Новые резервные коды:\n${regen.recovery_codes.join('\n')}`);
      setMessage('Recovery-коды обновлены');
    });
  };

  const linkProvider = async (providerId: string) => {
    setMessage(null);
    setError(null);
    await safe(`link:${providerId}`, async () => {
      const data = await onLinkProvider(providerId);
      const method = (data?.method || 'GET').toUpperCase();
      if (method === 'POST') {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = data.authorize_url;
        document.body.appendChild(form);
        form.submit();
      } else {
        window.location.href = data.authorize_url;
      }
    });
  };

  const unlinkProvider = async (providerId: string) => {
    setMessage(null);
    setError(null);
    await safe(`unlink:${providerId}`, async () => {
      await onUnlinkProvider(providerId);
      setMessage('Провайдер отвязан');
    });
  };

  return (
    <div className="stack">
      <div className="card">
        <h3>{t('security.password')}</h3>
        <div className="form-grid">
          <label>
            <span>{t('security.currentPassword')}</span>
            <input
              type="password"
              value={passwordForm.current}
              onChange={(e) => setPasswordForm({ ...passwordForm, current: e.target.value })}
            />
          </label>
          <label>
            <span>{t('security.newPassword')}</span>
            <input
              type="password"
              value={passwordForm.next}
              onChange={(e) => setPasswordForm({ ...passwordForm, next: e.target.value })}
            />
          </label>
        </div>
        <button className="primary-button" onClick={submitPassword} disabled={!!busy.pwd}>
          {t('security.changePassword')}
        </button>
      </div>

      <div className="card">
        <h3>{t('security.totp')}</h3>
        <p className="muted">{mfaStatus?.has_totp ? '2FA включена' : '2FA не включена'}</p>

        {!emailVerified && (
          <p className="muted">{t('security.totp.emailVerificationRequired')}</p>
        )}

        <div className="row" style={{ gap: 10 }}>
          {!mfaStatus?.has_totp ? (
            <button
              className="primary-button"
              onClick={beginTotp}
              disabled={!emailVerified || !!busy.totpBegin}
              title={!emailVerified ? t('security.totp.emailVerificationRequired') : undefined}
            >
              {t('security.totp.enable')}
            </button>
          ) : (
            <button className="ghost-button" onClick={disableTotp} disabled={!!busy.totpDisable}>
              {t('security.totp.disable')}
            </button>
          )}

          <button
            className="ghost-button"
            disabled={(!mfaStatus?.has_totp && !mfaStatus?.has_webauthn) || !!busy.regen}
            onClick={regenRecovery}
          >
            Обновить recovery-коды
          </button>
        </div>

        {totpSetup && (
          <div className="mfa-box">
            <div className="qr-wrap">
              <img src={totpSetup.svg_data_uri} alt="QR" />
            </div>
            <label>
              <span>{t('login.mfa')}</span>
              <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} />
            </label>
            <button className="secondary-button" onClick={confirmTotp} disabled={!!busy.totpConfirm}>
              Подтвердить 2FA
            </button>
          </div>
        )}
      </div>

      <div className="card">
        <h3>{t('security.passkeys')}</h3>
        {passkeys.length === 0 && <p className="muted">{t('security.passkeys.empty')}</p>}

        <div className="list">
          {passkeys.map((pk: any) => (
            <div key={pk.id} className="list-row">
              <div>
                <strong>{pk.name || 'Passkey'}</strong>
                <span className="muted">{pk.is_passwordless ? 'Passwordless' : requiresMfa ? 'MFA' : 'Passkey'}</span>
              </div>
              <button
                className="ghost-button"
                onClick={() => onDeletePasskey(pk.id)}
                disabled={!!busy[`pk:${pk.id}`]}
              >
                Удалить
              </button>
            </div>
          ))}
        </div>

        <button className="secondary-button" onClick={onAddPasskey} disabled={!!busy.addPk}>
          {t('security.passkeys.add')}
        </button>
      </div>

      <div className="card">
        <h3>{t('security.providers')}</h3>
        {providers.length === 0 && <p className="muted">{t('security.providers.empty')}</p>}

        <div className="list">
          {providers.map((provider) => {
            const linked = linkedProviders.has(provider.id);
            return (
              <div key={provider.id} className="list-row">
                <div>
                  <strong>{provider.name}</strong>
                  <span className="muted">
                    {linked ? t('security.providers.linked') : t('security.providers.unlinked')}
                  </span>
                </div>

                {linked ? (
                  <button
                    className="ghost-button"
                    onClick={() => unlinkProvider(provider.id)}
                    disabled={!!busy[`unlink:${provider.id}`]}
                  >
                    {t('security.providers.unlink')}
                  </button>
                ) : (
                  <button
                    className="ghost-button"
                    onClick={() => linkProvider(provider.id)}
                    disabled={!!busy[`link:${provider.id}`]}
                  >
                    {t('security.providers.link')}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
