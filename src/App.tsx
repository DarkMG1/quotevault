import { AuthProvider, useAuth } from './hooks/useAuth';
import { Layout } from './components/Layout';
import { Feed } from './components/Feed';
import { CryptoProvider } from './hooks/useCrypto';
import { QuotesProvider } from './hooks/useQuotes';
import { Component, lazy, Suspense, useEffect, useState, type ReactNode } from 'react';
import { useRegisterSW } from 'virtual:pwa-register/react';

const AuthUI = lazy(() => import('./components/Auth').then(m => ({ default: m.AuthUI })));
const AdminDashboard = lazy(() => import('./components/Admin').then(m => ({ default: m.AdminDashboard })));
const Profile = lazy(() => import('./components/Profile').then(m => ({ default: m.Profile })));

const Spinner = () => (
  <div className="min-h-screen flex items-center justify-center">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
  </div>
);

// React logs the caught error; this keeps a failed screen chunk from blanking the whole app.
class ScreenErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (!this.state.failed) return this.props.children;
    return <div role="alert" className="p-4">
      <p>This screen could not load. Check your connection and reload.</p>
      <button type="button" onClick={() => window.location.reload()} className="mt-3 rounded-lg bg-slate-800 px-3 py-2 text-sm">Reload</button>
    </div>;
  }
}

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
  const { user, loading, canSync, error, retry, isPasswordRecovery } = useAuth();
  const [currentPath, setCurrentPath] = useState(window.location.hash);

  useEffect(() => {
    const handleHashChange = () => setCurrentPath(window.location.hash);
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  if (loading) {
    return <Spinner />;
  }

  if (!user || isPasswordRecovery) {
    return <>
      {error && <div role="alert" className="fixed inset-x-4 top-4 z-[70] mx-auto max-w-xl rounded-xl border border-red-500/30 bg-red-950/90 p-4 text-red-200 shadow-xl">
        <p>{error}</p>
        <button type="button" onClick={() => void retry()} className="mt-3 rounded-lg bg-red-500/20 px-3 py-2 text-sm font-medium hover:bg-red-500/30">Retry connection</button>
      </div>}
      <ScreenErrorBoundary><Suspense fallback={<Spinner />}><AuthUI /></Suspense></ScreenErrorBoundary>
    </>;
  }

  const screen = currentPath === '#admin' || currentPath === '#profile' ? currentPath : '#';
  return (
    <CryptoProvider key={user.id}>
      <QuotesProvider>
      <Layout currentPath={currentPath}>
        {!canSync && <p role="status" className="p-4 text-sm text-slate-300">Using saved quotes on this device. Sync resumes when your session reconnects. <button onClick={retry} className="text-primary-400 underline">Retry connection</button></p>}
        <ScreenErrorBoundary key={screen}><Suspense fallback={<Spinner />}>
        {!canSync && screen !== '#' ? (
          <p className="p-4">Connect and restore your session to manage account settings.</p>
        ) : currentPath === '#admin' ? (
          <AdminDashboard />
        ) : currentPath === '#profile' ? (
          <Profile />
        ) : (
          <Feed />
        )}
        </Suspense></ScreenErrorBoundary>
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
