import React from 'react';
import { useAuth } from '../lib/auth';
import { AppLoader } from './AppLoader';
import { Link, Navigate, useLocation } from 'react-router-dom';
import { useI18n } from '../lib/i18n';

type Props = {
  children: React.ReactNode;
};

export const AuthLoadingGuard: React.FC<Props> = ({ children }) => {
  const { loading, user, error, refresh } = useAuth();
  const { t } = useI18n();
  const location = useLocation();
  const loginPath = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;

  if (loading && !user) {
    return <AppLoader />;
  }

  if (error && !user) {
    return (
      <div className="card" role="alert">
        <p>{t(error)}</p>
        <button className="primary-button" type="button" onClick={() => void refresh()}>
          {t('common.retry')}
        </button>
        <Link className="ghost-button" to={loginPath}>{t('nav.login')}</Link>
      </div>
    );
  }

  if (!user) return <Navigate to={loginPath} replace />;

  return <>{children}</>;
};
