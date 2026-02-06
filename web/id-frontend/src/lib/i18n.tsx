import React, { createContext, useContext, useMemo, useState } from 'react';

export type Language = 'ru' | 'en';

type I18nContextValue = {
  language: Language;
  setLanguage: (next: Language) => void;
  t: (key: string) => string;
};

const RU: Record<string, string> = {
  'theme.label': 'Тема',
  'theme.system': 'Системная',
  'theme.light': 'Светлая',
  'theme.dark': 'Тёмная',
  'nav.login': 'Войти',
  'nav.logout': 'Выйти',
  'nav.account': 'Аккаунт',
  'home.title': 'Единый центр идентификации',
  'home.subtitle': 'Управляйте входом, безопасностью и доступами.',
  'home.cta': 'Перейти в аккаунт',
  'login.title': 'Вход',
  'login.subtitle': 'Введите данные для входа в UpdSpace ID.',
  'login.email': 'Email',
  'login.password': 'Пароль',
  'login.submit': 'Войти',
  'login.signup': 'Создать аккаунт',
  'login.passkey': 'Войти по Passkey',
  'login.providers': 'Провайдеры входа',
  'login.mfa': 'Код MFA',
  'login.recovery': 'Резервный код',
  'signup.title': 'Регистрация',
  'signup.subtitle': 'Создайте новый аккаунт.',
  'signup.username': 'Имя пользователя',
  'signup.email': 'Email',
  'signup.password': 'Пароль',
  'signup.language': 'Язык',
  'signup.birthDate': 'Дата рождения',
  'signup.minor': 'Мне меньше 18 лет',
  'signup.guardianEmail': 'Email опекуна',
  'signup.guardianConsent': 'Согласие опекуна получено',
  'signup.consentData': 'Согласие на обработку данных',
  'signup.consentMarketing': 'Согласие на маркетинг',
  'signup.submit': 'Зарегистрироваться',
  'authorize.title': 'Подтвердите доступ',
  'authorize.subtitle': 'Приложение запрашивает доступ к данным.',
  'authorize.deny': 'Отклонить',
  'authorize.approve': 'Разрешить',
  'authorize.approving': 'Подтверждение...',
  'authorize.switchAccount': 'Сменить аккаунт',
  'authorize.continue': 'Продолжить',
  'authorize.continuing': 'Переход...',
  'authorize.confirm.title': 'Подтверждение входа',
  'authorize.confirm.subtitle': 'Проверьте аккаунт и приложение.',
  'authorize.confirm.appLabel': 'Приложение',
  'authorize.confirm.accessGranted': 'Доступ будет предоставлен.',
  'account.title': 'Личный кабинет',
  'account.profile': 'Профиль',
  'account.security': 'Безопасность',
  'account.privacy': 'Приватность',
  'account.sessions': 'Сессии',
  'account.apps': 'Приложения',
  'account.data': 'Данные',
  'account.email.title': 'Email',
  'account.email.verified': 'Подтверждён',
  'account.email.unverified': 'Не подтверждён',
  'account.email.verifyHint': 'Подтвердите email для повышения безопасности.',
  'account.email.resend': 'Отправить письмо повторно',
  'account.email.resendSent': 'Письмо отправлено',
  'account.email.changeLabel': 'Новый email',
  'account.email.changeButton': 'Сменить email',
  'account.email.changeRequested': 'Запрос на смену email отправлен',
  'profile.firstName': 'Имя',
  'profile.lastName': 'Фамилия',
  'profile.phone': 'Телефон',
  'profile.birthDate': 'Дата рождения',
  'profile.save': 'Сохранить',
  'security.password': 'Пароль',
  'security.currentPassword': 'Текущий пароль',
  'security.newPassword': 'Новый пароль',
  'security.changePassword': 'Сменить пароль',
  'security.totp': 'Двухфакторная аутентификация',
  'security.totp.enable': 'Включить 2FA',
  'security.totp.disable': 'Отключить 2FA',
  'security.totp.emailVerificationRequired': 'Подтвердите email перед включением 2FA',
  'security.passkeys': 'Passkeys',
  'security.passkeys.empty': 'Пока нет passkeys',
  'security.passkeys.add': 'Добавить Passkey',
  'security.providers': 'OAuth-провайдеры',
  'security.providers.empty': 'Нет доступных провайдеров',
  'security.providers.linked': 'Подключён',
  'security.providers.unlinked': 'Не подключён',
  'security.providers.link': 'Подключить',
  'security.providers.unlink': 'Отключить',
  'preferences.language': 'Язык',
  'preferences.timezone': 'Часовой пояс',
  'preferences.timezone.notSelected': 'Не выбран',
  'preferences.marketing': 'Маркетинговые уведомления',
  'preferences.save': 'Сохранить настройки',
  'sessions.title': 'Активные сессии',
  'sessions.revokeAll': 'Завершить все остальные сессии',
  'apps.title': 'Подключённые приложения',
  'apps.revoke': 'Отозвать доступ',
  'data.export': 'Экспорт данных',
  'data.exportButton': 'Скачать данные',
  'data.reauthDescription': 'Подтвердите пароль для операции.',
  'data.delete': 'Удаление аккаунта',
  'data.deleteButton': 'Удалить аккаунт',
  'error.default_login': 'Не удалось выполнить вход',
  'error.default_signup': 'Не удалось выполнить регистрацию',
  'error.INVALID_CREDENTIALS': 'Неверный email или пароль',
  'error.SERVER_ERROR': 'Ошибка сервера',
};

const EN: Record<string, string> = {
  'theme.label': 'Theme',
  'theme.system': 'System',
  'theme.light': 'Light',
  'theme.dark': 'Dark',
  'nav.login': 'Login',
  'nav.logout': 'Logout',
  'nav.account': 'Account',
};

const dictionaries: Record<Language, Record<string, string>> = {
  ru: RU,
  en: { ...RU, ...EN },
};

const I18nContext = createContext<I18nContextValue | undefined>(undefined);

export const I18nProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [language, setLanguage] = useState<Language>('ru');

  const value = useMemo<I18nContextValue>(
    () => ({
      language,
      setLanguage,
      t: (key: string) => dictionaries[language][key] ?? key,
    }),
    [language],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
};

export const useI18n = (): I18nContextValue => {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error('useI18n must be used within I18nProvider');
  }
  return ctx;
};
