import { Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from './lib/auth';
import { useI18n } from './lib/i18n';
import { ThemeSetting, useTheme } from './lib/theme';

const AppLayout = () => {
  const { user, logout } = useAuth();
  const { t } = useI18n();
  const { setting, setTheme } = useTheme();
  const location = useLocation();
  const inAccount = location.pathname.startsWith('/account');

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link to="/" className="brand">
          <span className="brand-mark">ID</span>
          <span className="brand-name">UpdSpace</span>
        </Link>
        <div className="header-actions">
          <div className="theme-control">
            <label htmlFor="theme-select" className="visually-hidden">
              {t('theme.label')}
            </label>
            <select
              id="theme-select"
              value={setting}
              onChange={(event) => setTheme(event.target.value as ThemeSetting)}
            >
              <option value="system">{t('theme.system')}</option>
              <option value="light">{t('theme.light')}</option>
              <option value="dark">{t('theme.dark')}</option>
            </select>
          </div>
          {user ? (
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
          ) : (
            <Link className="ghost-button" to="/login">
              {t('nav.login')}
            </Link>
          )}
        </div>
      </header>
      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
};

export default AppLayout;
