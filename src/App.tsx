import { AuthProvider, useAuth } from './hooks/useAuth';
import { AuthUI } from './components/Auth';
import { Layout } from './components/Layout';
import { Feed } from './components/Feed';
import { AdminDashboard } from './components/Admin';
import { Profile } from './components/Profile';
import { CryptoProvider } from './hooks/useCrypto';
import { useEffect, useState } from 'react';

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
    <CryptoProvider>
      <Layout currentPath={currentPath}>
        {currentPath === '#admin' ? (
          <AdminDashboard />
        ) : currentPath === '#profile' ? (
          <Profile />
        ) : (
          <Feed />
        )}
      </Layout>
    </CryptoProvider>
  );
};

function App() {
  return (
    <AuthProvider>
      <ProtectedRoute />
    </AuthProvider>
  );
}

export default App;
