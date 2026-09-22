import React from 'react';

export const SuccessBanner: React.FC<{ message: string }> = ({ message }) => {
  return <div className="success-banner" role="status">{message}</div>;
};

export const ErrorBanner: React.FC<{ message: string }> = ({ message }) => {
  return <div className="error-banner" role="alert">{message}</div>;
};
