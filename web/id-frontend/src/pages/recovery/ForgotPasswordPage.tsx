import { Link } from 'react-router-dom';
import { useI18n } from '../../lib/i18n';
import { EmailRequestForm } from './EmailRequestForm';

const ForgotPasswordPage = () => {
  const { t } = useI18n();
  return (
    <div className="auth-panel recovery-panel">
      <h2>{t('recovery.title')}</h2>
      <p className="muted">{t('recovery.description')}</p>
      <EmailRequestForm />
      <p><Link to="/login">{t('nav.login')}</Link></p>
    </div>
  );
};
export default ForgotPasswordPage;
