import { useState, useEffect } from 'react';
import axios from 'axios';

interface Task {
  task_id: string;
  status: string;
}

function PixelIcon({ type, className = '' }: { type: 'shield' | 'database' | 'lock' | 'scan' | 'alert' | 'check'; className?: string }) {
  const icons = {
    shield: (
      <svg width="32" height="32" viewBox="0 0 32 32" className={className}>
        <rect x="4" y="8" width="24" height="20" fill="currentColor" />
        <polygon points="4,8 16,2 28,8" fill="currentColor" />
        <rect x="10" y="14" width="4" height="4" fill="#0f0f1a" />
        <rect x="18" y="14" width="4" height="4" fill="#0f0f1a" />
        <rect x="12" y="20" width="8" height="4" fill="#0f0f1a" />
      </svg>
    ),
    database: (
      <svg width="32" height="32" viewBox="0 0 32 32" className={className}>
        <rect x="4" y="8" width="24" height="18" fill="currentColor" />
        <rect x="2" y="2" width="28" height="10" fill="currentColor" />
        <rect x="4" y="10" width="24" height="2" fill="#0f0f1a" />
        <rect x="4" y="16" width="24" height="2" fill="#0f0f1a" />
        <rect x="4" y="22" width="24" height="2" fill="#0f0f1a" />
      </svg>
    ),
    lock: (
      <svg width="32" height="32" viewBox="0 0 32 32" className={className}>
        <rect x="8" y="16" width="16" height="14" fill="currentColor" />
        <rect x="6" y="14" width="20" height="4" fill="currentColor" />
        <rect x="10" y="20" width="4" height="8" fill="#0f0f1a" />
        <rect x="18" y="20" width="4" height="8" fill="#0f0f1a" />
        <circle cx="16" cy="10" r="6" fill="currentColor" />
        <circle cx="16" cy="10" r="2" fill="#0f0f1a" />
      </svg>
    ),
    scan: (
      <svg width="32" height="32" viewBox="0 0 32 32" className={className}>
        <rect x="4" y="4" width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" />
        <rect x="10" y="10" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" />
        <rect x="14" y="14" width="4" height="4" fill="currentColor" />
        <line x1="4" y1="16" x2="8" y2="16" stroke="currentColor" strokeWidth="2" />
        <line x1="24" y1="16" x2="28" y2="16" stroke="currentColor" strokeWidth="2" />
        <line x1="16" y1="4" x2="16" y2="8" stroke="currentColor" strokeWidth="2" />
        <line x1="16" y1="24" x2="16" y2="28" stroke="currentColor" strokeWidth="2" />
      </svg>
    ),
    alert: (
      <svg width="32" height="32" viewBox="0 0 32 32" className={className}>
        <polygon points="16,2 28,28 4,28" fill="currentColor" />
        <polygon points="16,6 24,24 8,24" fill="#0f0f1a" />
        <circle cx="16" cy="18" r="3" fill="#0f0f1a" />
      </svg>
    ),
    check: (
      <svg width="32" height="32" viewBox="0 0 32 32" className={className}>
        <rect x="4" y="4" width="24" height="24" fill="currentColor" />
        <line x1="8" y1="16" x2="14" y2="22" stroke="#0f0f1a" strokeWidth="3" />
        <line x1="14" y1="22" x2="24" y2="10" stroke="#0f0f1a" strokeWidth="3" />
      </svg>
    ),
  };
  return icons[type];
}

function PixelHeader({ apiStatus }: { apiStatus: 'loading' | 'success' | 'error' }) {
  return (
    <header className="pixel-border" style={{ background: '#1a1a2e', padding: '16px 24px' }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="pixel-glow">
            <PixelIcon type="shield" className="text-green" />
          </div>
          <div>
            <h1 className="pixel-title text-green" style={{ fontSize: '12px', margin: 0 }}>
              SECAGENT
            </h1>
            <p className="text-muted" style={{ fontSize: '6px', marginTop: '4px' }}>
              SECURITY ANALYSIS SYSTEM
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <PixelIcon 
            type={apiStatus === 'success' ? 'check' : apiStatus === 'error' ? 'alert' : 'database'} 
            className={apiStatus === 'success' ? 'text-green' : apiStatus === 'error' ? 'text-red' : 'text-yellow pixel-blink'} 
          />
          <div className="text-sm">
            <span className={apiStatus === 'success' ? 'text-green' : apiStatus === 'error' ? 'text-red' : 'text-yellow'}>
              {apiStatus === 'loading' ? '[ LOADING ]' : apiStatus === 'success' ? '[ ONLINE ]' : '[ ERROR ]'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

function PixelCard({ title, children, className = '' }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`pixel-card ${className}`} style={{ padding: '16px' }}>
      <h2 className="pixel-title text-green" style={{ fontSize: '10px', marginBottom: '16px', paddingBottom: '8px', borderBottom: '2px solid #00ff00' }}>
        {'>'} {title}
      </h2>
      {children}
    </div>
  );
}

function StatCard({ icon, label, value, color }: { icon: 'shield' | 'database' | 'lock'; label: string; value: string | number; color: string }) {
  return (
    <div className="pixel-card" style={{ padding: '16px', textAlign: 'center' }}>
      <PixelIcon type={icon} className={color} />
      <p className="text-muted text-xs mt-2">{label}</p>
      <p className={color} style={{ fontSize: '16px', fontWeight: 'bold', marginTop: '8px' }}>{value}</p>
    </div>
  );
}

function TaskItem({ task, index }: { task: Task; index: number }) {
  const statusColors = {
    pending: 'text-yellow',
    completed: 'text-green',
    default: 'text-muted',
  };
  const statusLabels = {
    pending: 'PENDING',
    completed: 'COMPLETED',
  };

  return (
    <div className="pixel-border" style={{ background: '#16213e', padding: '12px 16px', marginBottom: '8px' }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="text-muted text-xs">[{String(index + 1).padStart(2, '0')}]</span>
          <span className="text-sm" style={{ wordBreak: 'break-all' }}>{task.task_id}</span>
        </div>
        <span className={`text-xs ${statusColors[task.status as keyof typeof statusColors] || statusColors.default}`}>
          [{statusLabels[task.status as keyof typeof statusLabels] || task.status.toUpperCase()}]
        </span>
      </div>
    </div>
  );
}

function LoadingAnimation() {
  return (
    <div className="flex justify-center items-center py-8">
      <div className="flex gap-2">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className="w-4 h-4 bg-green"
            style={{
              animation: `pixelBlink 0.8s ease-in-out ${i * 0.1}s infinite`,
            }}
          />
        ))}
      </div>
      <span className="text-green text-xs ml-4">SCANNING...</span>
    </div>
  );
}

function App() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [apiStatus, setApiStatus] = useState<'loading' | 'success' | 'error'>('loading');

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/tasks');
      setTasks((prev) => [...prev, response.data]);
      setApiStatus('success');
    } catch (error) {
      console.error('Failed to create task:', error);
      setApiStatus('error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  return (
    <div style={{ minHeight: '100vh', background: '#0f0f1a', display: 'flex', flexDirection: 'column' }}>
      <div className="pixel-scanline" />
      <PixelHeader apiStatus={apiStatus} />
      
      <main style={{ flex: 1, padding: '32px 24px', maxWidth: '800px', margin: '0 auto', width: '100%' }}>
        <div className="text-center mb-8">
          <h2 className="pixel-title" style={{ fontSize: '18px', color: '#fff', marginBottom: '12px' }}>
            SECURITY INTELLIGENCE
          </h2>
          <h3 className="pixel-title text-green" style={{ fontSize: '14px', marginBottom: '12px' }}>
            ANALYSIS PLATFORM
          </h3>
          <p className="text-muted" style={{ fontSize: '8px' }}>
            BASED ON LARGE LANGUAGE MODEL
          </p>
          <p className="text-muted" style={{ fontSize: '8px', marginTop: '4px' }}>
            CODE VULNERABILITY DETECTION & MALWARE ANALYSIS
          </p>
        </div>

        <div className="flex justify-center gap-6 mb-8">
          <button className="pixel-button" onClick={() => {}}>
            <span className="flex items-center gap-2">
              <PixelIcon type="scan" className="w-5 h-5" />
              VULNERABILITY SCAN
            </span>
          </button>
          <button className="pixel-button" onClick={() => {}}>
            <span className="flex items-center gap-2">
              <PixelIcon type="alert" className="w-5 h-5" />
              MALWARE ANALYSIS
            </span>
          </button>
        </div>

        <PixelCard title="SYSTEM STATUS" className="mb-6">
          <div className="grid grid-cols-3 gap-4">
            <StatCard icon="shield" label="API STATUS" value={apiStatus === 'loading' ? 'CHECKING' : apiStatus === 'success' ? 'NORMAL' : 'ERROR'} color={apiStatus === 'success' ? 'text-green' : apiStatus === 'error' ? 'text-red' : 'text-yellow'} />
            <StatCard icon="database" label="TASK COUNT" value={tasks.length} color="text-blue" />
            <StatCard icon="lock" label="SECURITY LEVEL" value="HIGH" color="text-purple" />
          </div>
        </PixelCard>

        <PixelCard title="RECENT TASKS">
          {loading ? (
            <LoadingAnimation />
          ) : tasks.length > 0 ? (
            <div className="space-y-3">
              {tasks.map((task, index) => (
                <TaskItem key={task.task_id} task={task} index={index} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <PixelIcon type="alert" className="text-yellow mx-auto mb-4" />
              <p className="text-muted text-xs">NO TASKS FOUND</p>
              <p className="text-muted text-xs mt-2">PRESS BUTTON BELOW TO CREATE NEW TASK</p>
            </div>
          )}
          <div className="mt-6 flex justify-end">
            <button className="pixel-button" onClick={fetchTasks} disabled={loading}>
              {loading ? 'PROCESSING...' : 'NEW TASK'}
            </button>
          </div>
        </PixelCard>
      </main>

      <footer className="pixel-border" style={{ background: '#1a1a2e', padding: '16px', textAlign: 'center', marginTop: 'auto' }}>
        <p className="text-muted text-xs">
          SECAGENT SECURITY INTELLIGENCE ANALYSIS PLATFORM
        </p>
        <p className="text-muted text-xs mt-2">
          [ 2026 ALL RIGHTS RESERVED ]
        </p>
      </footer>
    </div>
  );
}

export default App;
