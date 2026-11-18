import { HelmetProvider } from 'react-helmet-async';
import { SEO } from './components/SEO.jsx';

export default function App() {
  return (
    <HelmetProvider>
      <SEO title="Rides" description="Group rides near you" />
      <main>Helmet and safety gear required on every ride.</main>
    </HelmetProvider>
  );
}
