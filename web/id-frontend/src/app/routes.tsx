import React from 'react';
import { createBrowserRouter, Outlet } from 'react-router-dom';

import AppLayout from '../App';
import { AppLoader } from '../components/AppLoader';
import { AuthLoadingGuard } from '../components/AuthLoadingGuard';
import { useI18n } from '../lib/i18n';

const RouteError = () => {
  const { t } = useI18n();
  return (
    <div className="card" role="alert">
      <p>{t('error.pageUnavailable')}</p>
      <button type="button" onClick={() => window.location.reload()}>{t('common.retry')}</button>
    </div>
  );
};

type LazyModule = { default: React.ComponentType };

const lazyPage =
  (importer: () => Promise<LazyModule>) =>
  async () => {
    const mod = await importer();
    return { Component: mod.default };
  };

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    HydrateFallback: AppLoader,
    ErrorBoundary: RouteError,
    children: [
      { index: true, lazy: lazyPage(() => import('../pages/home/HomePage')) },

      { path: 'login', lazy: lazyPage(() => import('../pages/login/LoginPage')) },
      { path: 'forgot-password', lazy: lazyPage(() => import('../pages/recovery/ForgotPasswordPage')) },
      { path: 'reset-password', lazy: lazyPage(() => import('../pages/recovery/ResetPasswordPage')) },
      { path: 'verify-email', lazy: lazyPage(() => import('../pages/recovery/VerifyEmailPage')) },
      { path: 'signup', lazy: lazyPage(() => import('../pages/signup/SignupPage')) },
      {
        element: <AuthLoadingGuard><Outlet /></AuthLoadingGuard>,
        children: [
          { path: 'authorize', lazy: lazyPage(() => import('../pages/authorize/AuthorizePage')) },
          { path: 'account', lazy: lazyPage(() => import('../pages/account/AccountRoute')) },
        ],
      },
    ],
  },
]);
