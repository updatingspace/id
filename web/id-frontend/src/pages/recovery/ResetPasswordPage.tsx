import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';
import { recoveryError } from './errors';

const ResetPasswordPage = () => {
  const { t } = useI18n();
  const { logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [key] = useState(() => new URLSearchParams(location.hash.slice(1)).get('key') || '');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (loading) return;
    setError(null);
    if (password !== confirmation) { setError(t('recovery.mismatch')); return; }
    setLoading(true);
    try {
      await api.resetPassword(key, password);
      await logout();
      setPassword('');
      setConfirmation('');
      setDone(true);
      void navigate('/reset-password', { replace: true });
    } catch (err) {
      setError(recoveryError(err, t));
    } finally {
      setLoading(false);
    }
  };
  return (
    <div className="auth-panel recovery-panel">
      <h2>{t('recovery.newTitle')}</h2>
      {done ? <p role="status">{t('recovery.changed')}</p> : !key ? (
        <p role="alert">{t('error.INVALID_RECOVERY_LINK')}</p>
      ) : (
        <form className="form-stack" onSubmit={submit} aria-busy={loading}>
          <label><span>{t('recovery.newPassword')}</span>
            <input type="password" autoComplete="new-password" required maxLength={4096}
              value={password} onChange={(event) => setPassword(event.target.value)} /></label>
          <label><span>{t('recovery.confirmPassword')}</span>
            <input type="password" autoComplete="new-password" required maxLength={4096}
              value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
          {error && <div role="alert" className="error-banner">{error}</div>}
          <button className="primary-button" type="submit" disabled={loading}>{t('recovery.save')}</button>
        </form>
      )}
      {!done && <p><Link to="/forgot-password">{t('recovery.requestAgain')}</Link></p>}
      <p><Link to="/login">{t('nav.login')}</Link></p>
    </div>
  );
};
export default ResetPasswordPage;
