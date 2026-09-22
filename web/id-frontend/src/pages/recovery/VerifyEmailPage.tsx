import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';
import { useI18n } from '../../lib/i18n';
import { EmailRequestForm } from './EmailRequestForm';
import { recoveryError } from './errors';

const VerifyEmailPage = () => {
  const { t } = useI18n();
  const location = useLocation();
  const navigate = useNavigate();
  const [key] = useState(() => new URLSearchParams(location.hash.slice(1)).get('key') || '');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = async () => {
    if (loading) return;
    setLoading(true);
    setError(null);
    try {
      await api.confirmEmail(key);
      setDone(true);
      void navigate('/verify-email', { replace: true });
    } catch (err) {
      setError(recoveryError(err, t));
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="auth-panel recovery-panel">
      <h2>{t('signup.verifyTitle')}</h2>
      {done ? <p role="status">{t('recovery.verified')}</p> : (
        <>
          {key && <>
            <p>{t('recovery.verifyDescription')}</p>
            <button className="primary-button" type="button" disabled={loading} onClick={confirm}>
              {t('recovery.confirmEmail')}
            </button>
          </>}
          {error && <div role="alert" className="error-banner">{error}</div>}
          {(!key || error) && <><p>{t('recovery.resendDescription')}</p><EmailRequestForm verification /></>}
        </>
      )}
      <p><Link to="/login">{t('nav.login')}</Link></p>
    </div>
  );
};
export default VerifyEmailPage;
