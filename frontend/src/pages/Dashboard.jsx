import React, { useState, useEffect, useContext } from 'react';
import { Activity, ShieldAlert, FileAudio, Info, Loader2 } from 'lucide-react';
import { fetchWithColdStart } from '../api';
import { ServerStatusContext } from '../App';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const { setWarmingUp } = useContext(ServerStatusContext);

  useEffect(() => {
    let mounted = true;

    async function loadStats() {
      try {
        const data = await fetchWithColdStart('/api/dashboard-data', {}, setWarmingUp);
        if (mounted) {
          setStats(data);
          setError(null);
        }
      } catch (err) {
        if (mounted) setError(err.message || "Failed to load dashboard data.");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadStats();

    return () => { mounted = false; };
  }, [setWarmingUp]);

  return (
    <div>
      <h1 className="page-title">Live Session Dashboard</h1>
      <p className="page-subtitle">Real-time threat statistics for the current active server session.</p>
      
      <div className="card" style={{ backgroundColor: '#fff5e5', border: '1px solid #ffe0b2' }}>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
          <Info color="#995c00" />
          <div style={{ color: '#995c00' }}>
            <strong>Ephemeral Data Notice</strong>
            <p style={{ margin: '0.5rem 0 0 0', fontSize: '0.95rem' }}>
              For your privacy, this tool does not use a database. These statistics are stored in memory only and will reset to zero whenever the server goes to sleep (after ~15 minutes of inactivity on the free tier).
            </p>
          </div>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
          <Loader2 size={32} style={{ animation: 'spin 2s linear infinite', marginBottom: '1rem' }} />
          <p>Fetching live stats...</p>
        </div>
      ) : error ? (
        <div className="result-banner danger">
          <Info className="icon" />
          <div><strong>Error:</strong> {error}</div>
        </div>
      ) : (
        <div className="stat-grid">
          <div className="stat-card">
            <Activity color="var(--accent-color)" size={32} style={{ marginBottom: '1rem' }} />
            <div className="stat-value">{stats?.total_scans || 0}</div>
            <div className="stat-label">Total Scans</div>
          </div>
          
          <div className="stat-card">
            <ShieldAlert color="var(--danger-color)" size={32} style={{ marginBottom: '1rem' }} />
            <div className="stat-value">{stats?.phishing_detected || 0}</div>
            <div className="stat-label">Phishing Blocked</div>
          </div>
          
          <div className="stat-card">
            <FileAudio color="var(--warning-color)" size={32} style={{ marginBottom: '1rem' }} />
            <div className="stat-value">{stats?.deepfakes_detected || 0}</div>
            <div className="stat-label">Deepfakes Found</div>
          </div>
        </div>
      )}
    </div>
  );
}
