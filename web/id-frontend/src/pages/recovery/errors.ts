export const recoveryError = (error: unknown, t: (key: string) => string): string => {
  if (error && typeof error === 'object') {
    const code = 'code' in error && typeof error.code === 'string' ? error.code : '';
    const translated = t(`error.${code}`);
    if (code && translated !== `error.${code}`) return translated;
    if (code === 'VALIDATION_ERROR' && 'message' in error && typeof error.message === 'string') return error.message;
  }
  return t('recovery.failed');
};
