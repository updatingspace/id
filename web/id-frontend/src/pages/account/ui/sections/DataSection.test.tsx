import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { DataSection } from './DataSection';

const t = (k: string) => k;

describe('DataSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('exports data with mfa code when MFA is required', async () => {
    const onExport = vi.fn().mockResolvedValue({ payload: { foo: 'bar' } });
    const onDelete = vi.fn().mockResolvedValue(undefined);
    const setError = vi.fn();
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const createObjectURL = vi.fn(() => 'blob:export-url');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });

    render(
      <DataSection
        t={t}
        requiresMfa
        onExport={onExport}
        onDelete={onDelete}
        onDone={vi.fn()}
        setError={setError}
      />,
    );

    await userEvent.type(screen.getByLabelText('security.currentPassword'), 'pwd-1');
    await userEvent.type(screen.getByLabelText('login.mfa'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'data.exportButton' }));

    await waitFor(() => {
      expect(onExport).toHaveBeenCalledWith({ password: 'pwd-1', mfa_code: '123456' });
      expect(createObjectURL).toHaveBeenCalledTimes(1);
      expect(clickSpy).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:export-url');
      expect(setError).toHaveBeenCalledWith(null);
    });
  });

  it('deletes account only after user confirmation', async () => {
    const onDelete = vi.fn().mockResolvedValue(undefined);
    const onDone = vi.fn();
    const confirmMock = vi.fn(() => true);
    vi.stubGlobal('confirm', confirmMock);

    render(
      <DataSection
        t={t}
        requiresMfa={false}
        onExport={vi.fn().mockResolvedValue({})}
        onDelete={onDelete}
        onDone={onDone}
        setError={vi.fn()}
      />,
    );

    await userEvent.type(screen.getByLabelText('security.currentPassword'), 'pwd-2');
    await userEvent.click(screen.getByRole('button', { name: 'data.deleteButton' }));

    await waitFor(() => {
      expect(onDelete).toHaveBeenCalledWith({ password: 'pwd-2', mfa_code: undefined, reason: 'user_request' });
      expect(onDone).toHaveBeenCalledTimes(1);
      expect(confirmMock).toHaveBeenCalledTimes(1);
    });
  });
});
