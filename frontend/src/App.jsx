import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { ShieldCheck, Mic, LayoutDashboard, AppWindow, Loader2 } from 'lucide-react';
import Home from './pages/Home';
import AudioScan from './pages/AudioScan';
import Dashboard from './pages/Dashboard';
import ExtensionInfo from './pages/ExtensionInfo';
import './index.css';

export const ServerStatusContext = React.createContext({
  isWarmingUp: false,
  setWarmingUp: () => {}
});

function App() {
  const [isWarmingUp, setWarmingUp] = useState(false);

  return (
    <ServerStatusContext.Provider value={{ isWarmingUp, setWarmingUp }}>
      <Router>
        <div className="app-container">
          <nav className="nav">
            <NavLink to="/" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldCheck size={18} />
                Text Scan
              </div>
            </NavLink>
            <NavLink to="/audio" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Mic size={18} />
                Voice Scan
              </div>
            </NavLink>
            <NavLink to="/dashboard" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <LayoutDashboard size={18} />
                Dashboard
              </div>
            </NavLink>
            <NavLink to="/extension" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AppWindow size={18} />
                Extension
              </div>
            </NavLink>
          </nav>

          {isWarmingUp && (
            <div className="cold-start-warning">
              <Loader2 size={18} className="icon" style={{ animation: 'spin 2s linear infinite' }} />
              <div>
                <strong>Warming up the secure server...</strong>
                <p style={{ margin: 0, fontSize: '0.85rem' }}>This can take ~30s on the free tier. Please hold on.</p>
              </div>
            </div>
          )}

          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/audio" element={<AudioScan />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/extension" element={<ExtensionInfo />} />
          </Routes>

          <style dangerouslySetInnerHTML={{__html: `
            @keyframes spin { 100% { transform: rotate(360deg); } }
          `}} />
        </div>
      </Router>
    </ServerStatusContext.Provider>
  );
}

export default App;
