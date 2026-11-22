import { createAuth0Client } from '@auth0/auth0-spa-js';
const auth0 = await createAuth0Client({ domain: 'acme.eu.auth0.com', clientId: 'spa' });
export async function api(path: string, init: RequestInit = {}) {
  const token = await auth0.getTokenSilently();
  return fetch(`https://billing.acme.test/api${path}`, { ...init, headers: { Authorization: `Bearer ${token}` } });
}
