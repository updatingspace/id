import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';

export const AuthActions = () => {
  const { user, logout } = useAuth();
  const { t } = useI18n();
  const location = useLocation();
  const inAccount = location.pathname.startsWith('/account');

  if (!user) {
    return (
      <Link className="ghost-button" to="/login">
        {t('nav.login')}
      </Link>
    );
  }

  return (
    <>
      {!inAccount && (
        <Link className="ghost-button" to="/account">
          {t('nav.account')}
        </Link>
      )}
      <button type="button" className="ghost-button" onClick={logout}>
        {t('nav.logout')}
      </button>
    </>
  );
};
