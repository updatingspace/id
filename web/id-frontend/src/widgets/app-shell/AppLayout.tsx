import React from 'react';
import { Outlet } from 'react-router-dom';
import { AppHeader } from './AppHeader';

const AppLayout = () => (
  <div className="app-shell">
    <AppHeader />
    <main className="app-main">
      <Outlet />
    </main>
  </div>
);

export default AppLayout;
