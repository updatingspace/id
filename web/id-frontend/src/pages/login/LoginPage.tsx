import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

import { api } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';
import { setSessionToken } from '../../lib/session';
import { mapRequestOptions, serializeCredential } from '../../lib/webauthn';

import { SkeletonBlock } from '../../shared/ui/skeleton/SkeletonBlock';
import { SkeletonText } from '../../shared/ui/skeleton/SkeletonText';

const ProvidersSkeleton = () => (
  <div className="provider-stack">
    <SkeletonText width={140} />
    <div style={{ height: 10 }} />
    <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
      <SkeletonBlock width={140} height={36} radius={999} />
      <SkeletonBlock width={160} height={36} radius={999} />
      <SkeletonBlock width={120} height={36} radius={999} />
    </div>
  </div>
);

const LoginPage = () => {
  const { user, login } = useAuth();
  const { t } = useI18n();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const [mfaCode, setMfaCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);

  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);

  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const [providers, setProviders] = useState<{ id: string; name: string }[]>([]);
  const [providersLoading, setProvidersLoading] = useState(true);

  const redirectTo = new URLSearchParams(location.search).get('next') || '/account';

  useEffect(() => {
    if (user) {
      if (redirectTo.startsWith('/')) {
        navigate(redirectTo);
      } else {
        window.location.href = redirectTo;
      }
    }
  }, [user, redirectTo, navigate]);

  const getErrorMessage = (code?: string, message?: string): string => {
    if (code) {
      const translated = t(`error.${code}`);
      if (translated !== `error.${code}`) return translated;
    }
    return message || t('error.default_login');
  };

  useEffect(() => {
    let active = true;
    setProvidersLoading(true);

    api
      .getOAuthProviders()
      .then((data) => {
        if (!active) return;
        setProviders(data.providers || []);
      })
      .catch(() => {
        // ignore
      })
      .finally(() => {
        if (active) setProvidersLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const launchProviderLogin = async (providerId: string) => {
    setError(null);
    try {
      const data = await api.getOAuthLoginUrl(providerId, redirectTo);
      const method = (data.method || 'GET').toUpperCase();
      if (method === 'POST') {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = data.authorize_url;
        document.body.appendChild(form);
        form.submit();
      } else {
        window.location.href = data.authorize_url;
      }
    } catch (err: any) {
      setError(err?.message || 'Не удалось открыть провайдера');
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    const res = await login(
      email,
      password,
      useRecovery ? undefined : mfaCode,
      useRecovery ? recoveryCode : undefined,
    );

    setLoading(false);

    if (!res.ok) {
      if (res.code === 'MFA_REQUIRED') {
        setMfaRequired(true);
        return;
      }
      setError(getErrorMessage(res.code, res.message));
      return;
    }

    setRecoveryCodes(res.recoveryCodes || null);
    navigate(redirectTo);
  };

  const handlePasskey = async () => {
    setError(null);
    try {
      const start = await api.passkeyLoginBegin();
      const requestOptions = mapRequestOptions(start.request_options);
      const credential = (await navigator.credentials.get({ publicKey: requestOptions })) as PublicKeyCredential;
      const serialized = serializeCredential(credential);
      const complete = await api.passkeyLoginComplete(serialized);
      const token =
        complete?.access_token ||
        complete?.meta?.session_token ||
        complete?.session_token ||
        '';

      if (token) setSessionToken(token);
      window.location.href = redirectTo;
    } catch (err: any) {
      setError(getErrorMessage(err?.code, err?.message));
    }
  };

  return (
    <div className="auth-grid">
      <div className="auth-panel">
        <h2>{t('login.title')}</h2>
        <p className="muted">{t('login.subtitle')}</p>

        <form onSubmit={submit} className="form-stack">
          <label>
            <span>{t('login.email')}</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
          </label>

          <label>
            <span>{t('login.password')}</span>
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" required />
          </label>

          {mfaRequired && (
            <div className="mfa-box">
              <label>
                <span>{useRecovery ? t('login.recovery') : t('login.mfa')}</span>
                <input
                  value={useRecovery ? recoveryCode : mfaCode}
                  onChange={(e) => (useRecovery ? setRecoveryCode(e.target.value) : setMfaCode(e.target.value))}
                  required
                />
              </label>

              <button type="button" className="link-button" onClick={() => setUseRecovery((prev) => !prev)}>
                {useRecovery ? t('login.mfa') : t('login.recovery')}
              </button>
            </div>
          )}

          {error && <div className="error-banner">{error}</div>}

          <button className="primary-button" type="submit" disabled={loading}>
            {t('login.submit')}
          </button>
        </form>

        <button className="secondary-button" type="button" onClick={handlePasskey}>
          {t('login.passkey')}
        </button>

        {providersLoading ? (
          <ProvidersSkeleton />
        ) : (
          providers.length > 0 && (
            <div className="provider-stack">
              <span className="muted">{t('login.providers')}</span>
              <div className="row">
                {providers.map((provider) => (
                  <button
                    key={provider.id}
                    className="ghost-button"
                    type="button"
                    onClick={() => launchProviderLogin(provider.id)}
                  >
                    {provider.name}
                  </button>
                ))}
              </div>
            </div>
          )
        )}

        <div className="auth-footer">
          <span className="muted">Нет аккаунта?</span>
          <Link to="/signup" className="link-button">
            {t('login.signup')}
          </Link>
        </div>

        {recoveryCodes && recoveryCodes.length > 0 && (
          <div className="recovery-box">
            <h4>Новые резервные коды</h4>
            <p className="muted">Сохраните их в безопасном месте.</p>
            <div className="code-grid">
              {recoveryCodes.map((code) => (
                <span key={code}>{code}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="auth-aside">
        <div className="aside-card">
          <h3>Zero-trust Identity</h3>
          <p>Вход только через защищённые каналы, полная история сессий и контроль доступа.</p>
          <div className="aside-list">
            <span>• MFA + Passkeys</span>
            <span>• Consent per scope</span>
            <span>• Device alerts</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
