import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SessionsSection } from './SessionsSection';

const t = (k: string) => k;

describe('SessionsSection', () => {
  it('hides revoke button for current session and revokes non-current session', async () => {
    const onRevokeSession = vi.fn().mockResolvedValue(undefined);
    const onRevokeAll = vi.fn().mockResolvedValue(undefined);

    render(
      <SessionsSection
        t={t}
        sessions={[
          { id: 's1', user_agent: 'Current', current: true },
          { id: 's2', user_agent: 'Other', current: false },
        ]}
        onRevokeSession={onRevokeSession}
        onRevokeAll={onRevokeAll}
      />,
    );

    const revokeButtons = screen.getAllByRole('button', { name: 'Завершить' });
    expect(revokeButtons).toHaveLength(1);

    await userEvent.click(revokeButtons[0]);
    await waitFor(() => {
      expect(onRevokeSession).toHaveBeenCalledWith('s2');
    });
  });

  it('revokes all sessions', async () => {
    const onRevokeAll = vi.fn().mockResolvedValue(undefined);

    render(
      <SessionsSection
        t={t}
        sessions={[]}
        onRevokeSession={vi.fn().mockResolvedValue(undefined)}
        onRevokeAll={onRevokeAll}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'sessions.revokeAll' }));

    await waitFor(() => {
      expect(onRevokeAll).toHaveBeenCalledTimes(1);
    });
  });
});
