import { useState } from 'react';
import { api } from '../../lib/api';
import { useI18n } from '../../lib/i18n';
import { recoveryError } from './errors';

export const EmailRequestForm = ({ verification = false }: { verification?: boolean }) => {
  const { t } = useI18n();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (loading) return;
    setLoading(true);
    setError(null);
    setSent(false);
    try {
      if (verification) await api.requestEmailVerification(email.trim());
      else await api.requestPasswordReset(email.trim());
      setSent(true);
    } catch (err) {
      setError(recoveryError(err, t));
    } finally {
      setLoading(false);
    }
  };
  return (
    <form
      onSubmit={submit}
      onFocusCapture={() => api.prefetchFormToken(verification ? 'email_verification' : 'password_reset')}
      onChangeCapture={() => api.prefetchFormToken(verification ? 'email_verification' : 'password_reset')}
      className="form-stack"
      aria-busy={loading}
    >
      <label>
        <span>{t('login.email')}</span>
        <input type="email" autoComplete="email" required maxLength={254} value={email}
          onChange={(event) => { setEmail(event.target.value); setSent(false); }} />
      </label>
      {error && <div role="alert" className="error-banner">{error}</div>}
      {sent && <p role="status">{t(verification ? 'recovery.verificationSent' : 'recovery.sent')}</p>}
      <button className="primary-button" type="submit" disabled={loading}>
        {t(loading ? 'recovery.sending' : 'recovery.send')}
      </button>
      <p className="muted">{t('recovery.spam')}</p>
    </form>
  );
};
