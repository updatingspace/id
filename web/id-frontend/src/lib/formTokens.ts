export type FormTokenPurpose = 'login' | 'register' | 'password_reset' | 'email_verification';
export type FormToken = { form_token: string; expires_in: number };

type PreparedToken = {
  expiresAt: number;
  result: Promise<FormToken | null>;
};

// A prepared token belongs to exactly one submission, including failed or
// interrupted submissions. Keep it in memory only, separated by form purpose.
export const createFormTokenStore = (
  issue: (purpose: FormTokenPurpose) => Promise<FormToken>,
  now: () => number = Date.now,
) => {
  const prepared = new Map<FormTokenPurpose, PreparedToken>();

  const prefetch = (purpose: FormTokenPurpose): void => {
    const existing = prepared.get(purpose);
    if (existing && existing.expiresAt > now()) return;

    const startedAt = now();
    const entry: PreparedToken = {
      expiresAt: Infinity,
      result: Promise.resolve(null),
    };
    prepared.set(purpose, entry);
    entry.result = issue(purpose).then(
      (token) => {
        // Count network time against the TTL and leave room for submission.
        entry.expiresAt = startedAt + Math.max(0, token.expires_in * 1_000 - 5_000);
        return token;
      },
      () => {
        // Avoid retrying on every keystroke during an outage. Submission still
        // retries immediately because take() never returns a failed token.
        entry.expiresAt = now() + 5_000;
        return null;
      },
    );
  };

  const take = async (purpose: FormTokenPurpose): Promise<FormToken> => {
    const entry = prepared.get(purpose);
    // Reserve before awaiting so concurrent submissions cannot share a token.
    prepared.delete(purpose);
    if (entry) {
      const token = await entry.result;
      if (token && entry.expiresAt > now()) return token;
    }
    return issue(purpose);
  };

  return { prefetch, take };
};
