const SESSION_TOKEN_KEY = 'id_session_token';
let memorySessionToken: string | null = null;

const getSessionStorage = (): Storage | null => {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
};

export const getSessionToken = (): string | null => {
  const storage = getSessionStorage();
  if (storage) {
    const token = storage.getItem(SESSION_TOKEN_KEY);
    if (token) {
      memorySessionToken = token;
      return token;
    }
  }
  return memorySessionToken;
};

export const setSessionToken = (token: string): void => {
  const normalized = token.trim();
  memorySessionToken = normalized || null;

  const storage = getSessionStorage();
  if (!storage) {
    return;
  }

  if (normalized) {
    storage.setItem(SESSION_TOKEN_KEY, normalized);
  } else {
    storage.removeItem(SESSION_TOKEN_KEY);
  }
};

export const clearSessionToken = (): void => {
  memorySessionToken = null;
  const storage = getSessionStorage();
  if (storage) {
    storage.removeItem(SESSION_TOKEN_KEY);
  }
};
