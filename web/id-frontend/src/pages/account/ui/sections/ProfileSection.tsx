import React, { useState } from 'react';
import type { AccountUser } from '../../model/types';

type ProfilePayload = {
  first_name: string;
  last_name: string;
  phone_number: string;
  birth_date: string;
};

type Props = {
  t: (k: string) => string;
  user: AccountUser;
  emailVerified: boolean;
  emailAddress: string;
  onSaveProfile: (payload: ProfilePayload) => Promise<void>;
  onResendEmail: () => Promise<void>;
  onRequestEmailChange: (newEmail: string) => Promise<void>;
};

export const ProfileSection: React.FC<Props> = ({
  t,
  user,
  emailVerified,
  emailAddress,
  onSaveProfile,
  onResendEmail,
  onRequestEmailChange,
}) => {
  const [profileForm, setProfileForm] = useState<ProfilePayload>(() => ({
    first_name: user.first_name || '',
    last_name: user.last_name || '',
    phone_number: user.phone_number || '',
    birth_date: user.birth_date || '',
  }));
  const [emailForm, setEmailForm] = useState({ newEmail: '' });

  return (
    <div className="stack">
      <div className="card">
        <h3>{t('account.profile')}</h3>
        <div className="form-grid">
          <label>
            <span>{t('profile.firstName')}</span>
            <input value={profileForm.first_name} onChange={(e) => setProfileForm({ ...profileForm, first_name: e.target.value })} />
          </label>
          <label>
            <span>{t('profile.lastName')}</span>
            <input value={profileForm.last_name} onChange={(e) => setProfileForm({ ...profileForm, last_name: e.target.value })} />
          </label>
          <label>
            <span>{t('profile.phone')}</span>
            <input value={profileForm.phone_number} onChange={(e) => setProfileForm({ ...profileForm, phone_number: e.target.value })} />
          </label>
          <label>
            <span>{t('profile.birthDate')}</span>
            <input type="date" value={profileForm.birth_date} onChange={(e) => setProfileForm({ ...profileForm, birth_date: e.target.value })} />
          </label>
        </div>
        <button className="primary-button" onClick={() => onSaveProfile(profileForm)}>
          {t('profile.save')}
        </button>
      </div>

      <div className="card">
        <h3>{t('account.email.title')}</h3>
        <div className="list-row">
          <div>
            <strong>{emailAddress}</strong>
            <span className="muted">
              {emailVerified ? t('account.email.verified') : t('account.email.unverified')}
            </span>
          </div>
        </div>

        {!emailVerified && (
          <>
            <p className="muted">{t('account.email.verifyHint')}</p>
            <button className="ghost-button" onClick={onResendEmail} type="button">
              {t('account.email.resend')}
            </button>
          </>
        )}

        <div className="form-row">
          <label>
            <span>{t('account.email.changeLabel')}</span>
            <input
              type="email"
              value={emailForm.newEmail}
              onChange={(e) => setEmailForm({ newEmail: e.target.value })}
            />
          </label>
          <button
            type="button"
            className="secondary-button"
            onClick={() => onRequestEmailChange(emailForm.newEmail.trim())}
            disabled={!emailForm.newEmail.trim()}
          >
            {t('account.email.changeButton')}
          </button>
        </div>
      </div>
    </div>
  );
};
