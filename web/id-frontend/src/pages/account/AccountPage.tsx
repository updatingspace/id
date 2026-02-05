import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { useI18n } from '../../lib/i18n';
import { mapCreationOptions, serializeCredential } from '../../lib/webauthn';

import { useAccountData } from './model/useAccountData';
import type { AccountSection } from './model/types';

import { AccountHero } from './ui/AccountHero';
import { AccountHeroSkeleton } from './ui/AccountHeroSkeleton';
import { AccountNav } from './ui/AccountNav';
import { AccountNavSkeleton } from './ui/AccountNavSkeleton';
import { ErrorBanner, SuccessBanner } from './ui/banners';

import { ProfileSection } from './ui/sections/ProfileSection';
import { ProfileSectionSkeleton } from './ui/sections/ProfileSectionSkeleton';
import { SecuritySection } from './ui/sections/SecuritySection';
import { SecuritySectionSkeleton } from './ui/sections/SecuritySectionSkeleton';
import { PrivacySection } from './ui/sections/PrivacySection';
import { PrivacySectionSkeleton } from './ui/sections/PrivacySectionSkeleton';
import { SessionsSection } from './ui/sections/SessionsSection';
import { SessionsSectionSkeleton } from './ui/sections/SessionsSectionSkeleton';
import { AppsSection } from './ui/sections/AppsSection';
import { AppsSectionSkeleton } from './ui/sections/AppsSectionSkeleton';
import { DataSection } from './ui/sections/DataSection';
import { DataSectionSkeleton } from './ui/sections/DataSectionSkeleton';
import { LoginHistoryCard } from './ui/sections/LoginHistoryCard';
import { LoginHistorySkeleton } from './ui/sections/LoginHistorySkeleton';

const AccountPage = () => {
  const { user, loading: authLoading, refresh } = useAuth();
  const { t, language, setLanguage } = useI18n();
  const navigate = useNavigate();

  const [section, setSection] = useState<AccountSection>('profile');

  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !user) navigate('/login');
  }, [authLoading, user, navigate]);

  const enabled = !!user;
  const q = useAccountData(enabled);

  const emailVerified = q.emailStatus.data?.verified ?? user?.email_verified;
  const emailAddress = q.emailStatus.data?.email || user?.email || '';

  const displayName = useMemo(() => {
    const parts = [user?.first_name, user?.last_name].filter(Boolean).join(' ').trim();
    return parts || user?.username || user?.email || 'User';
  }, [user?.email, user?.first_name, user?.last_name, user?.username]);

  const requiresMfa = useMemo(() => {
    const mfa = q.mfa.data;
    if (mfa) return !!(mfa.has_totp || mfa.has_webauthn || mfa.has_recovery_codes);
    return Boolean(user?.has_2fa);
  }, [q.mfa.data, user?.has_2fa]);

  const tabs = useMemo(
    () =>
      [
        { id: 'profile', label: t('account.profile') },
        { id: 'security', label: t('account.security') },
        { id: 'privacy', label: t('account.privacy') },
        { id: 'sessions', label: t('account.sessions') },
        { id: 'apps', label: t('account.apps') },
        { id: 'data', label: t('account.data') },
      ] as Array<{ id: AccountSection; label: string }>,
    [t],
  );

  // ---- actions (оставляем в AccountPage, секции тонкие) ----

  const saveProfile = async (payload: any) => {
    setMessage(null);
    setError(null);
    try {
      await api.updateProfile(payload);
      await refresh();
      setMessage('Профиль обновлён');
    } catch (err: any) {
      setError(err?.message || 'Не удалось обновить профиль');
    }
  };

  const changePassword = async (current: string, next: string) => {
    setMessage(null);
    setError(null);
    try {
      await api.changePassword(current, next);
      setMessage('Пароль обновлён');
    } catch (err: any) {
      setError(err?.message || 'Не удалось обновить пароль');
    }
  };

  const savePreferences = async (nextPrefs: any) => {
    setMessage(null);
    setError(null);
    try {
      const updated = await api.updatePreferences(nextPrefs);
      if (updated.language && updated.language !== language) {
        setLanguage(updated.language === 'en' ? 'en' : 'ru');
      }
      setMessage('Предпочтения обновлены');
    } catch (err: any) {
      setError(err?.message || 'Не удалось обновить предпочтения');
    }
  };

  const addPasskey = async () => {
    setMessage(null);
    setError(null);
    try {
      const begin = await api.passkeysBegin(false);
      const publicKey = mapCreationOptions(begin.creation_options.publicKey || begin.creation_options);
      const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
      const serialized = serializeCredential(credential);
      const name = window.prompt('Название Passkey', 'Passkey') || 'Passkey';
      await api.passkeysComplete(name, serialized);
      await q.passkeys.refetch();
      setMessage('Passkey добавлен');
    } catch (err: any) {
      setError(err?.message || 'Не удалось добавить Passkey');
    }
  };

  const renderSection = () => {
    if (!user) return null;

    if (section === 'profile') {
      if (q.emailStatus.isLoading) return <ProfileSectionSkeleton />;
      return (
        <ProfileSection
          t={t}
          user={user}
          emailVerified={!!emailVerified}
          emailAddress={emailAddress}
          onSaveProfile={saveProfile}
          onResendEmail={async () => {
            setMessage(null);
            setError(null);
            try {
              await api.resendEmailVerification();
              setMessage(t('account.email.resendSent'));
            } catch (err: any) {
              setError(err?.message || t('error.SERVER_ERROR'));
            }
          }}
          onRequestEmailChange={async (newEmail: string) => {
            setMessage(null);
            setError(null);
            try {
              await api.changeEmail(newEmail);
              await q.emailStatus.refetch();
              setMessage(t('account.email.changeRequested'));
            } catch (err: any) {
              setError(err?.message || t('error.SERVER_ERROR'));
            }
          }}
        />
      );
    }

    if (section === 'security') {
      if (q.mfa.isLoading || q.passkeys.isLoading || q.providers.isLoading) return <SecuritySectionSkeleton />;
      return (
        <SecuritySection
          t={t}
          user={user}
          emailVerified={!!emailVerified}
          mfaStatus={q.mfa.data}
          passkeys={q.passkeys.data?.authenticators || []}
          providers={q.providers.data?.providers || []}
          requiresMfa={requiresMfa}
          onChangePassword={changePassword}
          onEnableTotp={api.totpBegin}
          onConfirmTotp={api.totpConfirm}
          onDisableTotp={api.totpDisable}
          onRegenRecovery={api.recoveryRegenerate}
          onAddPasskey={addPasskey}
          onDeletePasskey={async (id: string) => {
            await api.passkeysDelete([id]);
            await q.passkeys.refetch();
          }}
          onLinkProvider={async (providerId: string) => api.getOAuthLinkUrl(providerId, '/account')}
          onUnlinkProvider={async (providerId: string) => {
            await api.unlinkOAuthProvider(providerId);
            await refresh();
          }}
          setMessage={setMessage}
          setError={setError}
        />
      );
    }

    if (section === 'privacy') {
      if (q.preferences.isLoading || q.timezones.isLoading || q.consents.isLoading) return <PrivacySectionSkeleton />;
      return (
        <PrivacySection
          t={t}
          preferences={q.preferences.data}
          timezones={q.timezones.data?.timezones || []}
          consents={q.consents.data?.consents || []}
          onSave={savePreferences}
          onRevokeMarketing={async () => {
            await api.revokeConsent('marketing');
            await q.consents.refetch();
          }}
        />
      );
    }

    if (section === 'sessions') {
      if (q.sessions.isLoading) return <SessionsSectionSkeleton />;
      return (
        <SessionsSection
          t={t}
          sessions={q.sessions.data?.sessions || []}
          onRevokeSession={async (id: string) => {
            await api.revokeSession(id);
            await q.sessions.refetch();
          }}
          onRevokeAll={async () => {
            await api.revokeOtherSessions();
            await q.sessions.refetch();
          }}
        />
      );
    }

    if (section === 'apps') {
      if (q.apps.isLoading) return <AppsSectionSkeleton />;
      return (
        <AppsSection
          t={t}
          apps={q.apps.data?.items || []}
          onRevoke={async (clientId: string) => {
            await api.revokeOAuthApp(clientId);
            await q.apps.refetch();
          }}
        />
      );
    }

    // data
    if (q.mfa.isLoading) return <DataSectionSkeleton />;
    return (
      <DataSection
        t={t}
        requiresMfa={requiresMfa}
        onExport={api.dataExport}
        onDelete={api.deleteAccount}
        onDone={() => navigate('/login')}
        setError={setError}
      />
    );
  };

  const showNavSkeleton = q.anyInitialLoading;

  return (
    <div className="account-shell">
      {q.anyInitialLoading ? (
        <AccountHeroSkeleton />
      ) : (
        <AccountHero
          user={user}
          displayName={displayName}
          emailAddress={emailAddress}
          emailVerified={!!emailVerified}
          requiresMfa={requiresMfa}
          passkeysCount={q.passkeys.data?.authenticators?.length ?? 0}
          sessionsCount={q.sessions.data?.sessions?.length ?? 0}
        />
      )}

      <div className="account-layout">
        {showNavSkeleton ? (
          <AccountNavSkeleton />
        ) : (
          <AccountNav
            title={t('account.title')}
            tabs={tabs}
            section={section}
            onChangeSection={setSection}
            email={user?.email || emailAddress}
            emailVerified={!!emailVerified}
          />
        )}

        <section className="account-content">
          {message && <SuccessBanner message={message} />}
          {error && <ErrorBanner message={error} />}

          {renderSection()}

          {section === 'sessions' && (
            q.history.isLoading ? (
              <LoginHistorySkeleton />
            ) : (
              <LoginHistoryCard events={q.history.data?.events || []} />
            )
          )}
        </section>
      </div>
    </div>
  );
};

export default AccountPage;
