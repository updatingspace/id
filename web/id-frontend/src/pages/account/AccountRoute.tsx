import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import AccountPage from './AccountPage';

// Load the account data library only with this route. Each mount (including
// after a new login) gets its own cache.
export default function AccountRoute() {
  const [client] = useState(() => new QueryClient());
  return (
    <QueryClientProvider client={client}>
      <AccountPage />
    </QueryClientProvider>
  );
}
