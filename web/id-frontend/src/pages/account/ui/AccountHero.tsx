import React, { useMemo } from 'react';
import type { AccountUser } from '../model/types';

type BadgeTone = 'accent' | 'info' | 'muted' | 'danger';

type Props = {
  user: AccountUser | null;
  displayName: string;
  emailAddress: string;
  emailVerified: boolean;
  requiresMfa: boolean;
  passkeysCount: number;
  sessionsCount: number;
};

export const AccountHero: React.FC<Props> = ({
  user,
  displayName,
  emailAddress,
  emailVerified,
  requiresMfa,
  passkeysCount,
  sessionsCount,
}) => {
  const heroBadges = useMemo(() => {
    const badges: Array<{ key: string; text: string; tone: BadgeTone }> = [];
    if (emailVerified) badges.push({ key: 'email', text: 'Email verified', tone: 'accent' });
    if (user?.is_superuser) badges.push({ key: 'sys', text: 'System admin', tone: 'info' });
    if (user?.is_staff && !user?.is_superuser) badges.push({ key: 'staff', text: 'Staff', tone: 'info' });
    if (requiresMfa) badges.push({ key: 'mfa', text: '2FA enabled', tone: 'accent' });
    if (!emailVerified) badges.push({ key: 'email-unverified', text: 'Email not verified', tone: 'danger' });
    return badges;
  }, [emailVerified, requiresMfa, user?.is_staff, user?.is_superuser]);

  return (
    <div className="account-hero">
      <div className="account-hero-main">
        <div className="hero-avatar" aria-hidden>
          {user?.avatar_url ? (
            <img src={user.avatar_url} alt={displayName} />
          ) : (
            <span>{(displayName || 'U').slice(0, 1).toUpperCase()}</span>
          )}
        </div>

        <div className="hero-meta">
          <div className="hero-eyebrow">ID · Profile</div>
          <h1>{displayName}</h1>
          <div className="hero-subline">{emailAddress}</div>

          <div className="hero-badges">
            {heroBadges.map((b) => (
              <span key={b.key} className={`hero-badge tone-${b.tone}`}>
                {b.text}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="hero-actions">
        <div className="hero-stat">
          <span className="muted">2FA</span>
          <strong>{requiresMfa ? 'Enabled' : 'Disabled'}</strong>
        </div>
        <div className="hero-stat">
          <span className="muted">Passkeys</span>
          <strong>{passkeysCount}</strong>
        </div>
        <div className="hero-stat">
          <span className="muted">Sessions</span>
          <strong>{sessionsCount}</strong>
        </div>
      </div>
    </div>
  );
};
