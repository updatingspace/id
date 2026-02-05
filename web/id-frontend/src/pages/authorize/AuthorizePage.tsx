import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { api } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';

import { SkeletonBlock } from '../../shared/ui/skeleton/SkeletonBlock';
import { SkeletonText } from '../../shared/ui/skeleton/SkeletonText';

type ScopeRow = { name: string; description: string; required: boolean; granted: boolean };

type PreparePayload = {
  request_id: string;
  client: { client_id: string; name: string; logo_url?: string };
  scopes: ScopeRow[];
  consent_required: boolean;
  redirect_uri: string;
};

type ViewMode = 'loading' | 'consent' | 'confirm' | 'error';

const toErrorMessage = (err: unknown, fallback: string): string => {
  if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
    return err.message;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return fallback;
};

const ConsentSkeleton = () => (
  <div className="consent-card">
    <div className="consent-header" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
      <SkeletonBlock width={46} height={46} radius={14} />
      <div style={{ flex: 1 }}>
        <SkeletonText width={180} height={18} />
        <div style={{ height: 8 }} />
        <SkeletonText width="70%" />
      </div>
    </div>

    <div className="consent-body">
      <div style={{ height: 12 }} />
      <SkeletonBlock height={56} radius={14} />
      <div style={{ height: 12 }} />
      <div className="consent-scopes" style={{ display: 'grid', gap: 10 }}>
        {Array.from({ length: 4 }).map((_, i) => (
          <SkeletonBlock key={i} height={52} radius={14} />
        ))}
      </div>
      <div style={{ height: 14 }} />
      <div className="consent-actions" style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
        <SkeletonText width={140} />
        <div style={{ display: 'flex', gap: 10 }}>
          <SkeletonBlock width={120} height={40} radius={12} />
          <SkeletonBlock width={160} height={40} radius={12} />
        </div>
      </div>
    </div>
  </div>
);

const AuthorizePage = () => {
  const { user, logout } = useAuth();
  const { t } = useI18n();
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [data, setData] = useState<PreparePayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scopes, setScopes] = useState<Record<string, boolean>>({});
  const [viewMode, setViewMode] = useState<ViewMode>('loading');
  const [approving, setApproving] = useState(false);

  const query = useMemo(() => Object.fromEntries(params.entries()), [params]);

  useEffect(() => {
    const load = async () => {
      setViewMode('loading');
      setError(null);
      try {
        if (!user) {
          navigate(`/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
          return;
        }
        const result = await api.oidcPrepare(query as Record<string, string>);
        setData(result);

        const nextScopes: Record<string, boolean> = {};
        result.scopes.forEach((scope: ScopeRow) => {
          nextScopes[scope.name] = scope.required ? true : scope.granted;
        });
        setScopes(nextScopes);

        setViewMode(result.consent_required ? 'consent' : 'confirm');
      } catch (err: unknown) {
        setError(toErrorMessage(err, 'Не удалось подготовить запрос'));
        setViewMode('error');
      }
    };

    load();
  }, [user, query, navigate]);

  const toggleScope = (name: string) => {
    setScopes((prev) => ({ ...prev, [name]: !prev[name] }));
  };

  const approve = async () => {
    if (!data || approving) return;
    setApproving(true);
    try {
      const selected = Object.entries(scopes)
        .filter(([, value]) => value)
        .map(([name]) => name);

      const res = await api.oidcApprove({ request_id: data.request_id, scopes: selected, remember: true });
      window.location.assign(res.redirect_uri);
    } catch (err: unknown) {
      setError(toErrorMessage(err, 'Не удалось подтвердить вход'));
      setApproving(false);
    }
  };

  const deny = async () => {
    if (!data) return;
    const res = await api.oidcDeny(data.request_id);
    window.location.assign(res.redirect_uri);
  };

  const switchAccount = async () => {
    await logout();
    navigate(`/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);
  };

  if (viewMode === 'loading') return <ConsentSkeleton />;

  if (viewMode === 'error' || error) {
    return <div className="card error-banner">{error}</div>;
  }

  if (!data) return null;

  if (viewMode === 'confirm') {
    return (
      <div className="consent-card">
        <div className="consent-header">
          <div className="app-avatar">
            {data.client.logo_url ? <img src={data.client.logo_url} alt="logo" /> : data.client.name[0]}
          </div>
          <div>
            <h2>{t('authorize.confirm.title')}</h2>
            <p className="muted">{t('authorize.confirm.subtitle')}</p>
          </div>
        </div>

        <div className="consent-body">
          {user && (
            <div className="consent-user">
              <div className="user-avatar">{(user.email || '?')[0]?.toUpperCase()}</div>
              <div className="consent-user-info">
                <strong>{user.email}</strong>
                <span className="muted">{[user.first_name, user.last_name].filter(Boolean).join(' ')}</span>
              </div>
            </div>
          )}

          <div className="consent-app-info">
            <span className="muted">{t('authorize.confirm.appLabel')}</span>
            <span className="consent-app-name">{data.client.name}</span>
          </div>

          <p className="consent-granted-info">{t('authorize.confirm.accessGranted')}</p>

          <div className="consent-actions">
            <button className="link-button switch-account-link" onClick={switchAccount}>
              {t('authorize.switchAccount')}
            </button>

            <div className="consent-actions-primary">
              <button className="ghost-button" onClick={deny}>
                {t('authorize.deny')}
              </button>
              <button className="primary-button" onClick={approve} disabled={approving}>
                {approving ? t('authorize.continuing') : t('authorize.continue')}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="consent-card">
      <div className="consent-header">
        <div className="app-avatar">
          {data.client.logo_url ? <img src={data.client.logo_url} alt="logo" /> : data.client.name[0]}
        </div>
        <div>
          <h2>{t('authorize.title')}</h2>
          <p className="muted">{t('authorize.subtitle')}</p>
        </div>
      </div>

      <div className="consent-body">
        {user && (
          <div className="consent-user">
            <div className="user-avatar">{(user.email || '?')[0]?.toUpperCase()}</div>
            <div className="consent-user-info">
              <strong>{user.email}</strong>
              <span className="muted">{[user.first_name, user.last_name].filter(Boolean).join(' ')}</span>
            </div>
          </div>
        )}

        <div className="consent-app">{data.client.name}</div>

        <div className="consent-scopes">
          {data.scopes.map((scope) => (
            <label key={scope.name} className={`scope-row ${scope.required ? 'required' : ''}`}>
              <input
                type="checkbox"
                checked={scopes[scope.name] ?? false}
                disabled={scope.required}
                onChange={() => toggleScope(scope.name)}
              />
              <div>
                <strong>{scope.name}</strong>
                <span>{scope.description}</span>
              </div>
            </label>
          ))}
        </div>

        <div className="consent-actions">
          <button className="link-button switch-account-link" onClick={switchAccount}>
            {t('authorize.switchAccount')}
          </button>

          <div className="consent-actions-primary">
            <button className="ghost-button" onClick={deny}>
              {t('authorize.deny')}
            </button>
            <button className="primary-button" onClick={approve} disabled={approving}>
              {approving ? t('authorize.approving') : t('authorize.approve')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthorizePage;
