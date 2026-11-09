import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  FiTarget,
  FiFileText,
  FiActivity,
  FiCheckCircle,
  FiClock,
  FiAlertTriangle,
  FiXCircle,
} from 'react-icons/fi';

function QuickInfoPanel({ assessment, findings, scans, onRefresh }) {
  const navigate = useNavigate();
  const { id } = useParams();

  const severityCounts = findings.reduce(
    (acc, f) => {
      const sev = (f.severity || 'info').toLowerCase();
      if (acc[sev] !== undefined) acc[sev]++;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  const totalFindings = findings.length;
  const maxCount = Math.max(
    severityCounts.critical,
    severityCounts.high,
    severityCounts.medium,
    severityCounts.low,
    severityCounts.info,
    1
  );

  const severityConfig = [
    { key: 'critical', label: 'Critical', color: '#ef4444' },
    { key: 'high', label: 'High', color: '#f97316' },
    { key: 'medium', label: 'Medium', color: '#f59e0b' },
    { key: 'low', label: 'Low', color: '#3b82f6' },
    { key: 'info', label: 'Info', color: '#6b7280' },
  ];

  const getScanStatusIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'completed':
      case 'done':
        return <FiCheckCircle style={{ color: '#10b981' }} />;
      case 'running':
      case 'in_progress':
        return <FiActivity style={{ color: '#f59e0b' }} className="pulse-active" />;
      case 'error':
      case 'failed':
        return <FiXCircle style={{ color: '#ef4444' }} />;
      default:
        return <FiClock style={{ color: '#6b7280' }} />;
    }
  };

  const getStatusLabel = (status) => {
    switch (status?.toLowerCase()) {
      case 'in_progress':
      case 'in-progress':
        return 'In Progress';
      case 'completed':
        return 'Completed';
      default:
        return status || 'Created';
    }
  };

  return (
    <div className="quick-info-panel">
      {/* Assessment Info */}
      <div className="quick-info-section">
        <h6>Assessment</h6>
        {assessment ? (
          <>
            <div style={{ fontWeight: 600, fontSize: '0.88rem', marginBottom: 4, color: '#e5e7eb' }}>
              {assessment.name}
            </div>
            <div
              style={{
                fontSize: '0.78rem',
                color: '#00d4ff',
                fontFamily: "'Courier New', monospace",
                marginBottom: 8,
                display: 'flex',
                alignItems: 'center',
                gap: 4,
              }}
            >
              <FiTarget /> {assessment.target}
            </div>
            <span className={`status-badge ${assessment.status === 'in_progress' ? 'in-progress' : (assessment.status || 'created')}`}>
              {getStatusLabel(assessment.status)}
            </span>
          </>
        ) : (
          <div style={{ fontSize: '0.8rem', color: '#6b7280' }}>Loading...</div>
        )}
      </div>

      {/* Findings Summary */}
      <div className="quick-info-section">
        <h6>
          <FiAlertTriangle style={{ marginRight: 4 }} />
          Findings ({totalFindings})
        </h6>
        {severityConfig.map(({ key, label, color }) => (
          <div className="severity-bar" key={key}>
            <span className="bar-label">{label}</span>
            <div className="bar-fill">
              <div
                className="fill"
                style={{
                  width: `${(severityCounts[key] / maxCount) * 100}%`,
                  backgroundColor: color,
                }}
              />
            </div>
            <span className="bar-count" style={{ color }}>
              {severityCounts[key]}
            </span>
          </div>
        ))}
      </div>

      {/* Recent Scans */}
      <div className="quick-info-section">
        <h6>
          <FiActivity style={{ marginRight: 4 }} />
          Recent Scans
        </h6>
        {scans.length === 0 ? (
          <div style={{ fontSize: '0.78rem', color: '#6b7280', textAlign: 'center', padding: '8px 0' }}>
            No scans yet
          </div>
        ) : (
          scans.slice(0, 8).map((scan, idx) => (
            <div className="scan-item" key={scan.id || idx}>
              <span className="scan-status-icon">{getScanStatusIcon(scan.status)}</span>
              <span className="scan-name">
                {(scan.tool || scan.name || 'Scan').replace(/_/g, ' ')}
              </span>
            </div>
          ))
        )}
      </div>

      {/* Actions */}
      <button
        className="sidebar-new-btn"
        style={{ margin: 0 }}
        onClick={() => navigate(`/assessment/${id}/report`)}
      >
        <FiFileText /> Generate Report
      </button>
    </div>
  );
}

export default React.memo(QuickInfoPanel);
