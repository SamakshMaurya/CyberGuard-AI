import React, { useState, useEffect, useRef } from 'react';
import { FiTool, FiChevronDown, FiChevronUp, FiClock } from 'react-icons/fi';

const TOOL_ICONS = {
  nmap_scan: '🔍',
  web_scan: '🌐',
  nikto_scan: '🕷️',
  sqlmap_scan: '💉',
  directory_bruteforce: '📂',
  ssl_scan: '🔒',
  dns_enum: '📡',
  subdomain_enum: '🗂️',
  port_scan: '🔌',
  vuln_scan: '⚡',
  default: '🔧',
};

function ToolCallCard({ data }) {
  const { content, status, result } = data;
  const [showResult, setShowResult] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const timerRef = useRef(null);
  const startTimeRef = useRef(Date.now());

  const toolName = content?.tool || content?.name || 'Unknown Tool';
  const toolArgs = content?.args || content?.arguments || {};
  const icon = TOOL_ICONS[toolName] || TOOL_ICONS.default;

  useEffect(() => {
    if (status === 'running') {
      startTimeRef.current = Date.now();
      timerRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }, 1000);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [status]);

  useEffect(() => {
    if (status !== 'running' && timerRef.current) {
      clearInterval(timerRef.current);
    }
  }, [status]);

  const formatToolName = (name) => {
    return name
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  const formatDuration = (seconds) => {
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const renderResult = (res) => {
    if (!res) return null;
    if (typeof res === 'string') return res;
    try {
      return JSON.stringify(res, null, 2);
    } catch {
      return String(res);
    }
  };

  return (
    <div className={`tool-call-card ${status || 'running'}`}>
      <div className="tool-call-header">
        <span className="tool-icon">{icon}</span>
        <span className="tool-name">{formatToolName(toolName)}</span>
        <span className={`tool-status ${status || 'running'}`}>
          {status === 'running' && '⏳ Running'}
          {status === 'completed' && '✅ Complete'}
          {status === 'error' && '❌ Error'}
        </span>
      </div>

      {Object.keys(toolArgs).length > 0 && (
        <div className="tool-call-params">
          {Object.entries(toolArgs).map(([key, value]) => (
            <div key={key}>
              <span style={{ color: '#00d4ff' }}>{key}</span>:{' '}
              <span style={{ color: '#e5e7eb' }}>
                {typeof value === 'object' ? JSON.stringify(value) : String(value)}
              </span>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', marginTop: 8 }}>
        {result && (
          <button className="tool-call-toggle" onClick={() => setShowResult(!showResult)}>
            {showResult ? <FiChevronUp /> : <FiChevronDown />}
            {showResult ? 'Hide Result' : 'Show Result'}
          </button>
        )}
        <span className="tool-call-duration">
          <FiClock style={{ marginRight: 3 }} />
          {formatDuration(elapsed)}
        </span>
      </div>

      {showResult && result && (
        <div className="tool-call-result">
          <pre
            style={{
              fontSize: '0.75rem',
              color: '#e5e7eb',
              background: 'rgba(0,0,0,0.4)',
              padding: 10,
              borderRadius: 6,
              maxHeight: 300,
              overflow: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              margin: 0,
            }}
          >
            {renderResult(result)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default React.memo(ToolCallCard);
