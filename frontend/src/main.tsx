import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import { AppProvider } from './AppContext.tsx';
import './styles.css';

const el = document.getElementById('root');
if (!el) throw new Error('#root missing');
createRoot(el).render(<AppProvider><App /></AppProvider>);
