import { AuthProvider, useAuth } from './hooks/useAuth';
import { AuthUI } from './components/Auth';
import { Layout } from './components/Layout';
import { Feed } from './components/Feed';
import { AdminDashboard } from './components/Admin';
import { Profile } from './components/Profile';
import { CryptoProvider } from './hooks/useCrypto';
import { QuotesProvider } from './hooks/useQuotes';
import { useEffect, useState } from 'react';
import { useRegisterSW } from 'virtual:pwa-register/react';

function UpdateNotice() {
  const { needRefresh: [ready, setReady], updateServiceWorker } = useRegisterSW();
  if (!ready) return null;
  return <aside role="status" className="fixed bottom-0 inset-x-0 z-[60] bg-slate-800 border-t border-slate-600 p-4 flex flex-wrap items-center justify-center gap-3">
    <p className="text-sm">An update is ready. Finish saving your draft before reloading.</p>
    <button className="rounded bg-primary-600 px-3 py-2" onClick={() => void updateServiceWorker(true)}>Reload to update</button>
    <button className="rounded px-3 py-2" onClick={() => setReady(false)}>Later</button>
  </aside>;
}

const ProtectedRoute = () => {
  const { user, loading } = useAuth();
  const [currentPath, setCurrentPath] = useState(window.location.hash);

  useEffect(() => {
    const handleHashChange = () => setCurrentPath(window.location.hash);
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  if (!user) {
    return <AuthUI />;
  }

  return (
    <CryptoProvider key={user.id}>
      <QuotesProvider>
      <Layout currentPath={currentPath}>
        {currentPath === '#admin' ? (
          <AdminDashboard />
        ) : currentPath === '#profile' ? (
          <Profile />
        ) : (
          <Feed />
        )}
      </Layout>
      </QuotesProvider>
    </CryptoProvider>
  );
};

function App() {
  return (
    <AuthProvider>
      <ProtectedRoute />
      <UpdateNotice />
    </AuthProvider>
  );
}

export default App;
