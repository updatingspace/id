import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';

const SignupPage = () => {
  const { signup } = useAuth();
  const { t, language } = useI18n();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');

  const [lang, setLang] = useState<'ru' | 'en'>(language);
  const [timezone] = useState<string>(() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch {
      return '';
    }
  });

  const [consentData, setConsentData] = useState(false);
  const [consentMarketing, setConsentMarketing] = useState(false);

  const [isMinor, setIsMinor] = useState(false);
  const [guardianEmail, setGuardianEmail] = useState('');
  const [guardianConsent, setGuardianConsent] = useState(false);

  const [birthDate, setBirthDate] = useState('');

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const getErrorMessage = (code?: string, message?: string): string => {
    if (code) {
      const translated = t(`error.${code}`);
      if (translated !== `error.${code}`) return translated;
    }
    return message || t('error.default_signup');
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    const res = await signup({
      email,
      password,
      username: username || undefined,
      language: lang,
      timezone: timezone || undefined,
      consentDataProcessing: consentData,
      consentMarketing: consentMarketing,
      isMinor,
      guardianEmail: guardianEmail || undefined,
      guardianConsent,
      birthDate: birthDate || undefined,
    });

    setLoading(false);

    if (!res.ok) {
      setError(getErrorMessage(res.code, res.message));
      return;
    }

    navigate('/account');
  };

  return (
    <div className="auth-grid">
      <div className="auth-panel">
        <h2>{t('signup.title')}</h2>
        <p className="muted">{t('signup.subtitle')}</p>

        <form onSubmit={submit} className="form-stack">
          <label>
            <span>{t('signup.username')}</span>
            <input value={username} onChange={(e) => setUsername(e.target.value)} type="text" />
          </label>

          <label>
            <span>{t('signup.email')}</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
          </label>

          <label>
            <span>{t('signup.password')}</span>
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" required />
          </label>

          <label>
            <span>{t('signup.language')}</span>
            <select value={lang} onChange={(e) => setLang(e.target.value as 'ru' | 'en')}>
              <option value="ru">Русский</option>
              <option value="en">English</option>
            </select>
          </label>

          <div className="form-row">
            <label>
              <span>{t('signup.birthDate')}</span>
              <input value={birthDate} onChange={(e) => setBirthDate(e.target.value)} type="date" />
            </label>
          </div>

          <label className="checkbox-row">
            <input type="checkbox" checked={isMinor} onChange={(e) => setIsMinor(e.target.checked)} />
            <span>{t('signup.minor')}</span>
          </label>

          {isMinor && (
            <div className="minor-box">
              <label>
                <span>{t('signup.guardianEmail')}</span>
                <input value={guardianEmail} onChange={(e) => setGuardianEmail(e.target.value)} type="email" />
              </label>

              <label className="checkbox-row">
                <input type="checkbox" checked={guardianConsent} onChange={(e) => setGuardianConsent(e.target.checked)} />
                <span>{t('signup.guardianConsent')}</span>
              </label>
            </div>
          )}

          <label className="checkbox-row">
            <input type="checkbox" checked={consentData} onChange={(e) => setConsentData(e.target.checked)} />
            <span>{t('signup.consentData')}</span>
          </label>

          <label className="checkbox-row">
            <input type="checkbox" checked={consentMarketing} onChange={(e) => setConsentMarketing(e.target.checked)} />
            <span>{t('signup.consentMarketing')}</span>
          </label>

          {error && <div className="error-banner">{error}</div>}

          <button className="primary-button" type="submit" disabled={loading || !consentData}>
            {t('signup.submit')}
          </button>
        </form>

        <div className="auth-footer">
          <span className="muted">Уже есть аккаунт?</span>
          <Link to="/login" className="link-button">
            {t('nav.login')}
          </Link>
        </div>
      </div>

      <div className="auth-aside">
        <div className="aside-card">
          <h3>GDPR & 152-FZ ready</h3>
          <p>Минимальный сбор данных, прозрачные согласия и полный контроль над доступом.</p>
          <div className="aside-list">
            <span>• Privacy by default</span>
            <span>• Explicit consent</span>
            <span>• Data export</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SignupPage;
