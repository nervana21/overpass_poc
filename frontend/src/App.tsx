import { SetStateAction, useState } from 'react';
import './App.css';
import { Routes, Route } from 'react-router-dom';
import { Home } from './pages/Home';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { TestInterface } from './TestInterface';
import { User } from './types';

function App() {
  const [user, setUser] = useState<User | null>(null);

  return (
    <div className="App">
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register user={null} setUser={function (value: SetStateAction<User | null>): void {
          throw new Error('Function not implemented.');
        } } />} />
        <Route path="/test" element={<TestInterface />} />
      </Routes>
    </div>
  );
}

export default App;