import React, { useState, useContext } from 'react';
import { ShieldAlert, ShieldCheck, Info, Loader2 } from 'lucide-react';
import { fetchWithColdStart } from '../api';
import { ServerStatusContext } from '../App';

export default function Home() {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  
  const { setWarmingUp } = useContext(ServerStatusContext);

  const handleScan = async () => {
    if (!text.trim()) return;
    
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await fetchWithColdStart(
        '/api/scan-email', 
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text })
        },
        setWarmingUp
      );
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to reach the secure server. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Text Scanner</h1>
      <p className="page-subtitle">Paste any suspicious email or message below to check if it's an AI-generated phishing attempt.</p>
      
      <div className="card">
        <textarea 
          className="textarea"
          placeholder="Dear Customer, your account has been compromised. Click here immediately to verify your identity..."
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={loading}
        />
        
        <button 
          className="btn" 
          onClick={handleScan} 
          disabled={loading || !text.trim()}
        >
          {loading ? <><Loader2 size={18} style={{ animation: 'spin 2s linear infinite' }}/> Scanning...</> : 'Scan Message'}
        </button>

        {error && (
          <div className="result-banner danger" style={{ marginTop: '1rem' }}>
            <Info className="icon" />
            <div><strong>Error:</strong> {error}</div>
          </div>
        )}

        {result && (
          <div className={`result-banner ${result.is_ai_generated ? 'danger' : 'safe'}`}>
            {result.is_ai_generated ? <ShieldAlert className="icon" size={24} /> : <ShieldCheck className="icon" size={24} />}
            <div>
              <h3 style={{ margin: '0 0 0.5rem 0' }}>
                {result.is_ai_generated ? "Suspicious Content Detected" : "Looks Safe"}
              </h3>
              <p style={{ margin: 0 }}>{result.explanation}</p>
              <div style={{ marginTop: '1rem', fontSize: '0.85rem', opacity: 0.8 }}>
                Confidence: {result.confidence}% | Analysis Method: {result.method_used}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
