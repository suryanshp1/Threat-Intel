export async function logoutSession(fetcher: typeof fetch = fetch): Promise<void> {
  const response = await fetcher('/api/session', { method: 'DELETE' });
  if (!response.ok) throw new Error('Sign out could not be confirmed. Please retry.');
}
