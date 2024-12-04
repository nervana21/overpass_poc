import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import { TestInterface } from './TestInterface';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TestInterface />
  </StrictMode>,
);