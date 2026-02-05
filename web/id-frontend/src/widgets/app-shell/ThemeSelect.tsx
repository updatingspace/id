import React from 'react';
import { useI18n } from '../../lib/i18n';
import { ThemeSetting, useTheme } from '../../lib/theme';

export const ThemeSelect = () => {
  const { t } = useI18n();
  const { setting, setTheme } = useTheme();

  return (
    <div className="theme-control">
      <label htmlFor="theme-select" className="visually-hidden">
        {t('theme.label')}
      </label>
      <select
        id="theme-select"
        value={setting}
        onChange={(event) => setTheme(event.target.value as ThemeSetting)}
      >
        <option value="system">{t('theme.system')}</option>
        <option value="light">{t('theme.light')}</option>
        <option value="dark">{t('theme.dark')}</option>
      </select>
    </div>
  );
};
