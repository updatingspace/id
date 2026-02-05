import { Link } from 'react-router-dom';
import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';

const HomePage = () => {
  const { user } = useAuth();
  const { t } = useI18n();

  return (
    <section className="hero">
      <div className="hero-copy">
        <p className="eyebrow">UpdSpace Identity</p>
        <h1>{t('home.title')}</h1>
        <p className="lead">{t('home.subtitle')}</p>
        <div className="hero-actions">
          <Link className="primary-button" to={user ? '/account' : '/login'}>
            {t('home.cta')}
          </Link>
          {!user && (
            <Link className="ghost-button" to="/signup">
              {t('login.signup')}
            </Link>
          )}
        </div>
      </div>
      <div className="hero-card">
        <div className="hero-card-inner">
          <div className="hero-chip">SSO</div>
          <h3>Privacy by Design</h3>
          <p>
            Контролируйте, какие данные отправляются приложениям, управляйте
            сессиями и защищайте аккаунт с 2FA и Passkeys.
          </p>
          <div className="hero-metrics">
            <div>
              <span>2FA</span>
              <strong>Active</strong>
            </div>
            <div>
              <span>Passkeys</span>
              <strong>Ready</strong>
            </div>
            <div>
              <span>Consent</span>
              <strong>Granular</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HomePage;
