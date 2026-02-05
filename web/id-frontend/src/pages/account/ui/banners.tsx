import React from 'react';

export const SuccessBanner: React.FC<{ message: string }> = ({ message }) => {
  return <div className="success-banner">{message}</div>;
};

export const ErrorBanner: React.FC<{ message: string }> = ({ message }) => {
  return <div className="error-banner">{message}</div>;
};
