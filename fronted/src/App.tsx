
import { useState } from 'react';
import './App.css';
import RegisterWebAuthn from './components/RegisterWebAuthn';
import LoginWebAuthn from './components/LoginWebAuthn';

function App() {
  const [activeTab, setActiveTab] = useState('login');

  return (
    <div className="app-container">
      <h1>WebAuthn Demo</h1>
      
      <div className="tab-buttons">
        <button 
          className={activeTab === 'login' ? 'active' : ''}
          onClick={() => setActiveTab('login')}
        >
          Inicio de Sesión
        </button>
        <button 
          className={activeTab === 'register' ? 'active' : ''}
          onClick={() => setActiveTab('register')}
        >
          Registro
        </button>
      </div>
      
      <div className="tab-content">
        {activeTab === 'login' ? <LoginWebAuthn /> : <RegisterWebAuthn />}
      </div>
    </div>
  );
}

export default App;