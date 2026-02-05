import React from 'react';
import type { AccountSection } from '../model/types';

type Props = {
  title: string;
  tabs: Array<{ id: AccountSection; label: string }>;
  section: AccountSection;
  onChangeSection: (next: AccountSection) => void;
  email: string;
  emailVerified: boolean;
};

export const AccountNav: React.FC<Props> = ({
  title,
  tabs,
  section,
  onChangeSection,
  email,
  emailVerified,
}) => {
  return (
    <aside className="account-nav">
      <h2>{title}</h2>

      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`nav-pill ${section === tab.id ? 'active' : ''}`}
          onClick={() => onChangeSection(tab.id)}
          type="button"
        >
          {tab.label}
        </button>
      ))}

      <div className="account-summary">
        <strong>{email}</strong>
        <span>{emailVerified ? 'Email подтверждён' : 'Email не подтверждён'}</span>
      </div>
    </aside>
  );
};
