import React from 'react';
import { createBrowserRouter } from 'react-router-dom';

import AppLayout from '../widgets/app-shell/AppLayout';

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
    children: [
      { index: true, lazy: lazyPage(() => import('../pages/home/HomePage')) },

      { path: 'login', lazy: lazyPage(() => import('../pages/login/LoginPage')) },
      { path: 'signup', lazy: lazyPage(() => import('../pages/signup/SignupPage')) },
      { path: 'authorize', lazy: lazyPage(() => import('../pages/authorize/AuthorizePage')) },
      { path: 'account', lazy: lazyPage(() => import('../pages/account/AccountPage')) },
    ],
  },
]);
