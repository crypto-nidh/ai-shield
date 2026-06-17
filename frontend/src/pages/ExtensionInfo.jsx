import React from 'react';
import { AppWindow, Download, Settings, ShieldCheck } from 'lucide-react';
import { API_BASE_URL } from '../api';

export default function ExtensionInfo() {
  return (
    <div>
      <h1 className="page-title">Browser Extension</h1>
      <p className="page-subtitle">Protect yourself automatically while browsing Gmail and other webmail clients.</p>
      
      <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: '3rem' }}>
        <AppWindow size={64} color="var(--accent-color)" style={{ marginBottom: '1.5rem' }} />
        <h2 style={{ marginBottom: '1rem' }}>AI Shield for Chrome</h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '500px', marginBottom: '2rem' }}>
          Our browser extension seamlessly integrates into Gmail to automatically scan your incoming messages for AI-generated phishing attempts. 
          No technical knowledge required — it just works.
        </p>
        <a href={`${API_BASE_URL}/api/download-extension`} className="btn" style={{ marginBottom: '2rem' }} download="ai_shield_extension.zip">
          <Download size={20} />
          Download Extension (ZIP)
        </a>

        <div style={{ backgroundColor: '#f0f9ff', border: '1px solid #bae6fd', padding: '1rem', borderRadius: '8px', maxWidth: '500px', marginBottom: '3rem', textAlign: 'left', fontSize: '0.9rem', color: '#0369a1' }}>
          <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', marginTop: 0 }}>
            <ShieldCheck size={18} />
            Data Privacy Guarantee
          </h4>
          <p style={{ margin: 0 }}>
            Your privacy is our priority. Emails and audio files scanned by the extension are sent securely to our server, processed entirely in memory, and immediately deleted. <strong>No data is ever stored, logged, or shared.</strong>
          </p>
        </div>

        <div style={{ textAlign: 'left', width: '100%', maxWidth: '600px', borderTop: '1px solid #e5e5ea', paddingTop: '2rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Settings size={20} />
            Installation & Setup
          </h3>
          <ol style={{ paddingLeft: '1.5rem', color: 'var(--text-secondary)', lineHeight: '1.8' }}>
            <li>Extract the downloaded ZIP file to a folder on your computer.</li>
            <li>Open Chrome and navigate to <strong>chrome://extensions</strong>.</li>
            <li>Enable <strong>Developer mode</strong> in the top right corner.</li>
            <li>Click <strong>Load unpacked</strong> and select the folder you extracted.</li>
            <li>Click the AI Shield icon in your browser toolbar and click the gear icon to open Options.</li>
            <li>Ensure the API URL is set to: <code style={{ background: '#eee', padding: '0.2rem 0.4rem', borderRadius: '4px', color: '#333' }}>{API_BASE_URL}</code></li>
          </ol>
        </div>
      </div>
    </div>
  );
}
