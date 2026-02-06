import { beforeEach, describe, expect, it } from 'vitest';

import { clearSessionToken, getSessionToken, setSessionToken } from './session';

describe('session storage helpers', () => {
  beforeEach(() => {
    clearSessionToken();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it('stores and reads session token from sessionStorage', () => {
    setSessionToken('token-1');
    expect(getSessionToken()).toBe('token-1');
    expect(window.sessionStorage.getItem('id_session_token')).toBe('token-1');
    expect(window.localStorage.getItem('id_session_token')).toBeNull();
  });

  it('removes token when cleared or when empty value is set', () => {
    setSessionToken('token-2');
    setSessionToken('');
    expect(getSessionToken()).toBeNull();
    expect(window.sessionStorage.getItem('id_session_token')).toBeNull();

    setSessionToken('token-3');
    clearSessionToken();
    expect(getSessionToken()).toBeNull();
    expect(window.sessionStorage.getItem('id_session_token')).toBeNull();
  });
});
