import React from 'react';
import { BrandLink } from './BrandLink';
import { ThemeSelect } from './ThemeSelect';
import { AuthActions } from './AuthActions';

export const AppHeader = () => (
  <header className="app-header">
    <BrandLink />
    <div className="header-actions">
      <ThemeSelect />
      <AuthActions />
    </div>
  </header>
);
