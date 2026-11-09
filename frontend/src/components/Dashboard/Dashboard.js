import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FiShield,
  FiActivity,
  FiAlertTriangle,
  FiSearch,
  FiPlus,
  FiTarget,
  FiClock,
} from 'react-icons/fi';
import { getAssessments } from '../../services/api';
import NewAssessmentModal from './NewAssessmentModal';
import StatsChart from './StatsChart';
import { format } from 'date-fns';

function Dashboard() {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const navigate = useNavigate();

  const fetchAssessments = useCallback(async () => {
    try {
      const data = await getAssessments();
      const list = Array.isArray(data) ? data : data.assessments || [];
      setAssessments(list);
    } catch (err) {
      console.error('Failed to fetch assessments:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssessments();
  }, [fetchAssessments]);

  const totalAssessments = assessments.length;
  const activeScans = assessments.filter(
    (a) => a.status === 'in_progress' || a.status === 'in-progress'
  ).length;

  const allFindings = assessments.reduce(
    (acc, a) => {
      const f = a.findings_summary || a.findings_count || {};
      acc.critical += f.critical || 0;
      acc.high += f.high || 0;
      acc.medium += f.medium || 0;
      acc.low += f.low || 0;
      acc.info += f.info || 0;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  const totalFindings = allFindings.critical + allFindings.high + allFindings.medium + allFindings.low + allFindings.info;

  const getStatusBadgeClass = (status) => {
    switch (status?.toLowerCase()) {
      case 'in_progress':
      case 'in-progress':
        return 'in-progress';
      case 'completed':
        return 'completed';
      default:
        return 'created';
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
        return 'Created';
    }
  };

  const handleAssessmentCreated = (newAssessment) => {
    setShowModal(false);
    fetchAssessments();
    if (newAssessment?.id) {
      navigate(`/assessment/${newAssessment.id}`);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    try {
      return format(new Date(dateStr), 'MMM d, yyyy HH:mm');
    } catch {
      return dateStr;
    }
  };

  if (loading) {
    return (
      <div className="empty-state fade-in" style={{ height: '60vh' }}>
        <FiActivity className="empty-icon pulse-active" style={{ color: '#00d4ff' }} />
        <p>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h4 style={{ margin: 0, fontWeight: 700 }}>Dashboard</h4>
          <p style={{ margin: 0, fontSize: '0.85rem', color: '#9ca3af' }}>
            Overview of your VAPT assessments
          </p>
        </div>
        <button className="sidebar-new-btn" onClick={() => setShowModal(true)}>
          <FiPlus /> New Assessment
        </button>
      </div>

      {/* Stats Cards */}
      <div className="row g-3 mb-4">
        <div className="col-6 col-lg-3">
          <div className="dashboard-card">
            <div className="card-icon">
              <FiShield />
            </div>
            <div className="card-value">{totalAssessments}</div>
            <div className="card-label">Total Assessments</div>
          </div>
        </div>
        <div className="col-6 col-lg-3">
          <div className="dashboard-card">
            <div className="card-icon" style={{ color: activeScans > 0 ? '#f59e0b' : undefined }}>
              <FiActivity className={activeScans > 0 ? 'pulse-active' : ''} />
            </div>
            <div className="card-value">{activeScans}</div>
            <div className="card-label">Active Scans</div>
          </div>
        </div>
        <div className="col-6 col-lg-3">
          <div className="dashboard-card">
            <div className="card-icon">
              <FiSearch />
            </div>
            <div className="card-value">{totalFindings}</div>
            <div className="card-label">Total Findings</div>
          </div>
        </div>
        <div className="col-6 col-lg-3">
          <div className="dashboard-card critical-highlight">
            <div className="card-icon">
              <FiAlertTriangle />
            </div>
            <div className="card-value">{allFindings.critical}</div>
            <div className="card-label">Critical Findings</div>
          </div>
        </div>
      </div>

      <div className="row g-4">
        {/* Recent Assessments */}
        <div className="col-12 col-lg-8">
          <div style={{ marginBottom: 16 }}>
            <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Recent Assessments</h5>
          </div>

          {assessments.length === 0 ? (
            <div className="empty-state" style={{ minHeight: '200px' }}>
              <FiTarget className="empty-icon" />
              <p>No assessments yet. Create one to get started!</p>
              <button
                className="sidebar-new-btn"
                style={{ marginTop: 12 }}
                onClick={() => setShowModal(true)}
              >
                <FiPlus /> Create Assessment
              </button>
            </div>
          ) : (
            <div className="row g-3">
              {assessments.map((assessment) => {
                const findings = assessment.findings_summary || assessment.findings_count || {};
                return (
                  <div key={assessment.id} className="col-12 col-md-6">
                    <div
                      className="assessment-card"
                      onClick={() => navigate(`/assessment/${assessment.id}`)}
                    >
                      <div style={{ display: 'flex', alignItems: 'start', justifyContent: 'space-between', marginBottom: 4 }}>
                        <div className="assessment-name">{assessment.name}</div>
                        <span className={`status-badge ${getStatusBadgeClass(assessment.status)}`}>
                          {getStatusLabel(assessment.status)}
                        </span>
                      </div>
                      <div className="assessment-target">
                        <FiTarget style={{ marginRight: 4, fontSize: '0.75rem' }} />
                        {assessment.target}
                      </div>
                      <div className="assessment-meta">
                        <div className="severity-counts">
                          {(findings.critical || 0) > 0 && (
                            <span className="severity-count-dot critical">C:{findings.critical}</span>
                          )}
                          {(findings.high || 0) > 0 && (
                            <span className="severity-count-dot high">H:{findings.high}</span>
                          )}
                          {(findings.medium || 0) > 0 && (
                            <span className="severity-count-dot medium">M:{findings.medium}</span>
                          )}
                          {(findings.low || 0) > 0 && (
                            <span className="severity-count-dot low">L:{findings.low}</span>
                          )}
                        </div>
                        <span style={{ fontSize: '0.72rem', color: '#6b7280', display: 'flex', alignItems: 'center', gap: 4 }}>
                          <FiClock /> {formatDate(assessment.created_at)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Findings Distribution Chart */}
        <div className="col-12 col-lg-4">
          <div style={{ marginBottom: 16 }}>
            <h5 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Findings Distribution</h5>
          </div>
          <div className="dashboard-card">
            {totalFindings > 0 ? (
              <StatsChart findings={allFindings} total={totalFindings} />
            ) : (
              <div className="empty-state" style={{ minHeight: '180px' }}>
                <FiSearch className="empty-icon" />
                <p style={{ fontSize: '0.82rem' }}>No findings yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <NewAssessmentModal
        show={showModal}
        onHide={() => setShowModal(false)}
        onCreated={handleAssessmentCreated}
      />
    </div>
  );
}

export default Dashboard;
