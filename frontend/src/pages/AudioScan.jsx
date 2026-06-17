import React, { useState, useRef, useContext } from 'react';
import { UploadCloud, ShieldAlert, ShieldCheck, Info, Loader2 } from 'lucide-react';
import { fetchWithColdStart } from '../api';
import { ServerStatusContext } from '../App';

export default function AudioScan() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const { setWarmingUp } = useContext(ServerStatusContext);

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (selected) {
      setFile(selected);
      setResult(null);
      setError(null);
    }
  };

  const handleScan = async () => {
    if (!file) return;
    
    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const data = await fetchWithColdStart(
        '/api/scan-voice', 
        {
          method: 'POST',
          body: formData
        },
        setWarmingUp
      );
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to analyze audio. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Voice Scanner</h1>
      <p className="page-subtitle">Upload a voice note or audio file to detect if it's an AI-generated deepfake.</p>
      
      <div className="card">
        <div 
          className="upload-zone"
          onClick={() => fileInputRef.current?.click()}
        >
          <input 
            type="file" 
            accept="audio/*" 
            style={{ display: 'none' }} 
            ref={fileInputRef}
            onChange={handleFileChange}
          />
          <UploadCloud size={48} color="var(--accent-color)" style={{ marginBottom: '1rem' }} />
          <h3>{file ? file.name : "Click to select an audio file"}</h3>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
            Supports MP3, WAV, M4A up to 50MB
          </p>
        </div>

        <div style={{ marginTop: '1.5rem' }}>
          <button 
            className="btn" 
            onClick={handleScan} 
            disabled={loading || !file}
          >
            {loading ? <><Loader2 size={18} style={{ animation: 'spin 2s linear infinite' }}/> Analyzing Audio...</> : 'Scan Audio File'}
          </button>
        </div>

        {error && (
          <div className="result-banner danger" style={{ marginTop: '1rem' }}>
            <Info className="icon" />
            <div><strong>Error:</strong> {error}</div>
          </div>
        )}

        {result && (
          <div className={`result-banner ${result.is_deepfake ? 'danger' : 'safe'}`}>
            {result.is_deepfake ? <ShieldAlert className="icon" size={24} /> : <ShieldCheck className="icon" size={24} />}
            <div>
              <h3 style={{ margin: '0 0 0.5rem 0' }}>
                {result.is_deepfake ? "AI Deepfake Detected" : "Human Voice Verified"}
              </h3>
              <p style={{ margin: 0 }}>{result.explanation}</p>
              <div style={{ marginTop: '1rem', fontSize: '0.85rem', opacity: 0.8 }}>
                Confidence: {result.confidence}% | Method: {result.method_used}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
