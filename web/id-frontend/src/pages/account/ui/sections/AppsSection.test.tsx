import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppsSection } from './AppsSection';

const t = (k: string) => k;

describe('AppsSection', () => {
  it('calls revoke with client id', async () => {
    const onRevoke = vi.fn().mockResolvedValue(undefined);

    render(
      <AppsSection
        t={t}
        apps={[{ client_id: 'c1', name: 'Portal', scopes: ['openid', 'profile'] }]}
        onRevoke={onRevoke}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'apps.revoke' }));

    await waitFor(() => {
      expect(onRevoke).toHaveBeenCalledWith('c1');
    });
  });
});
