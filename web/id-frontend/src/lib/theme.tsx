import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';

export type ThemeSetting = 'system' | 'light' | 'dark';

type ThemeContextValue = {
  setting: ThemeSetting;
  setTheme: (next: ThemeSetting) => void;
};

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

const resolveTheme = (setting: ThemeSetting): 'light' | 'dark' => {
  if (setting === 'light' || setting === 'dark') {
    return setting;
  }
  if (typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    return 'dark';
  }
  return 'light';
};

export const ThemeProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [setting, setTheme] = useState<ThemeSetting>('system');

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolveTheme(setting);
  }, [setting]);

  const value = useMemo<ThemeContextValue>(() => ({ setting, setTheme }), [setting]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export const useTheme = (): ThemeContextValue => {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return ctx;
};
