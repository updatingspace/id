import React from 'react';
import { useAuth } from '../../lib/auth';
import { AppLoader } from '../../components/AppLoader';

type Props = {
  children: React.ReactNode;
};

export const AuthLoadingGuard: React.FC<Props> = ({ children }) => {
  const { loading } = useAuth();

  if (loading) {
    return <AppLoader />;
  }

  return <>{children}</>;
};
