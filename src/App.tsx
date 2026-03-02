import { AuthProvider, useAuth } from './hooks/useAuth';
import { AuthUI } from './components/Auth';
import { Layout } from './components/Layout';
import { Feed } from './components/Feed';

const ProtectedRoute = () => {
  const { user, loading } = useAuth();

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
    <Layout>
      <Feed />
    </Layout>
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
