import { describe, expect, it, vi } from 'vitest';
import { createFormTokenStore, type FormToken } from './formTokens';

const token = (id: string, expires_in = 900): FormToken => ({ form_token: id, expires_in });
const deferred = () => {
  let resolve!: (value: FormToken) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<FormToken>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

describe('prepared form tokens', () => {
  it('deduplicates interaction requests and reuses a ready token for one submission', async () => {
    const issue = vi.fn().mockResolvedValueOnce(token('first')).mockResolvedValueOnce(token('second'));
    const store = createFormTokenStore(issue);
    store.prefetch('login');
    store.prefetch('login');
    await Promise.resolve();
    store.prefetch('login');
    expect(await store.take('login')).toEqual(token('first'));
    expect(issue).toHaveBeenCalledTimes(1);
    expect(await store.take('login')).toEqual(token('second'));
    expect(issue).toHaveBeenCalledTimes(2);
  });

  it('joins an in-flight preparation without issuing a second token', async () => {
    const pending = deferred();
    const issue = vi.fn().mockReturnValue(pending.promise);
    const store = createFormTokenStore(issue);
    store.prefetch('login');
    const submission = store.take('login');
    pending.resolve(token('ready'));
    expect(await submission).toEqual(token('ready'));
    expect(issue).toHaveBeenCalledTimes(1);
  });

  it('reserves a pending token before awaiting so simultaneous submissions get distinct tokens', async () => {
    const pending = deferred();
    const issue = vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValueOnce(token('second'));
    const store = createFormTokenStore(issue);
    store.prefetch('login');
    const first = store.take('login');
    const second = store.take('login');
    pending.resolve(token('first'));
    expect(await first).toEqual(token('first'));
    expect(await second).toEqual(token('second'));
  });

  it('isolates purposes and supports submission without prior interaction', async () => {
    const issue = vi.fn().mockImplementation(async (purpose: string) => token(purpose));
    const store = createFormTokenStore(issue);
    store.prefetch('register');
    expect(await store.take('login')).toEqual(token('login'));
    expect(await store.take('register')).toEqual(token('register'));
    expect(await store.take('password_reset')).toEqual(token('password_reset'));
    expect(await store.take('email_verification')).toEqual(token('email_verification'));
    expect(issue).toHaveBeenCalledTimes(4);
  });

  it('replaces a token near expiry when the user resumes filling the form', async () => {
    let time = 0;
    const issue = vi.fn().mockResolvedValueOnce(token('old')).mockResolvedValueOnce(token('new'));
    const store = createFormTokenStore(issue, () => time);
    store.prefetch('login');
    await Promise.resolve();
    time = 895_000;
    store.prefetch('login');
    expect(await store.take('login')).toEqual(token('new'));
    expect(issue).toHaveBeenCalledTimes(2);
  });

  it('refreshes expired tokens on submission without replaying a credential request', async () => {
    let time = 0;
    const issue = vi.fn().mockResolvedValueOnce(token('old')).mockResolvedValueOnce(token('new'));
    const store = createFormTokenStore(issue, () => time);
    store.prefetch('login');
    await Promise.resolve();
    time = 900_000;
    expect(await store.take('login')).toEqual(token('new'));
  });

  it('includes time spent downloading the prepared token in its lifetime', async () => {
    let time = 0;
    const pending = deferred();
    const issue = vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValueOnce(token('fresh'));
    const store = createFormTokenStore(issue, () => time);
    store.prefetch('login');
    const submission = store.take('login');
    time = 896_000;
    pending.resolve(token('delayed'));
    expect(await submission).toEqual(token('fresh'));
  });

  it('recovers from a failed preparation with an on-demand request', async () => {
    const issue = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(token('fresh'));
    const store = createFormTokenStore(issue);
    store.prefetch('login');
    await Promise.resolve();
    expect(await store.take('login')).toEqual(token('fresh'));
  });

  it('does not discard a newer preparation when an already reserved request fails', async () => {
    const pending = deferred();
    const issue = vi.fn()
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(token('prepared-next'))
      .mockResolvedValueOnce(token('fallback'));
    const store = createFormTokenStore(issue);
    store.prefetch('login');
    const first = store.take('login');
    store.prefetch('login');
    pending.reject(new Error('offline'));
    expect(await first).toEqual(token('fallback'));
    expect(await store.take('login')).toEqual(token('prepared-next'));
    expect(issue).toHaveBeenCalledTimes(3);
  });

  it('backs off speculative failures while allowing immediate submission', async () => {
    const issue = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(token('fresh'));
    const store = createFormTokenStore(issue);
    store.prefetch('login');
    await Promise.resolve();
    store.prefetch('login');
    store.prefetch('login');
    expect(issue).toHaveBeenCalledTimes(1);
    expect(await store.take('login')).toEqual(token('fresh'));
  });

  it('surfaces an on-demand failure so the form can report it normally', async () => {
    const store = createFormTokenStore(vi.fn().mockRejectedValue(new Error('offline')));
    await expect(store.take('login')).rejects.toThrow('offline');
  });
});
