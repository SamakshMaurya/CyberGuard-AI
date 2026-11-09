import React, { useState, useEffect, useCallback } from 'react';
import { NavLink, useNavigate, useParams } from 'react-router-dom';
import { FiHome, FiPlus, FiTarget, FiActivity } from 'react-icons/fi';
import { getAssessments } from '../../services/api';
import NewAssessmentModal from '../Dashboard/NewAssessmentModal';

function Sidebar({ isOpen, onClose }) {
  const [assessments, setAssessments] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const navigate = useNavigate();
  const params = useParams();

  const fetchAssessments = useCallback(async () => {
    try {
      const data = await getAssessments();
      setAssessments(Array.isArray(data) ? data : data.assessments || []);
    } catch (err) {
      console.error('Failed to fetch assessments:', err);
    }
  }, []);

  useEffect(() => {
    fetchAssessments();
    const interval = setInterval(fetchAssessments, 15000);
    return () => clearInterval(interval);
  }, [fetchAssessments]);

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'in_progress':
      case 'in-progress':
        return '#f59e0b';
      case 'completed':
        return '#10b981';
      default:
        return '#3b82f6';
    }
  };

  const handleAssessmentCreated = (newAssessment) => {
    setShowModal(false);
    fetchAssessments();
    if (newAssessment?.id) {
      navigate(`/assessment/${newAssessment.id}`);
    }
  };

  return (
    <>
      <aside className={`sidebar ${isOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <button className="sidebar-new-btn" onClick={() => setShowModal(true)}>
            <FiPlus /> New Assessment
          </button>
        </div>

        <nav className="sidebar-nav">
          <NavLink
            to="/"
            end
            className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`}
            onClick={onClose}
          >
            <FiHome className="nav-icon" />
            <span>Dashboard</span>
          </NavLink>

          <div className="sidebar-section-title">Assessments</div>

          {assessments.length === 0 && (
            <div style={{ padding: '10px 16px', fontSize: '0.78rem', color: '#6b7280' }}>
              No assessments yet
            </div>
          )}

          {assessments.map((assessment) => (
            <NavLink
              key={assessment.id}
              to={`/assessment/${assessment.id}`}
              className={({ isActive }) => `sidebar-assessment-item ${isActive ? 'active' : ''}`}
              onClick={onClose}
            >
              <span
                className="status-dot"
                style={{ backgroundColor: getStatusColor(assessment.status) }}
              ></span>
              <FiTarget style={{ fontSize: '0.85rem', flexShrink: 0 }} />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {assessment.name}
              </span>
            </NavLink>
          ))}
        </nav>

        <div style={{ padding: '12px 16px', borderTop: '1px solid #1f2937', fontSize: '0.7rem', color: '#6b7280' }}>
          <FiActivity style={{ marginRight: 4 }} />
          {assessments.length} assessment{assessments.length !== 1 ? 's' : ''}
        </div>
      </aside>

      <NewAssessmentModal
        show={showModal}
        onHide={() => setShowModal(false)}
        onCreated={handleAssessmentCreated}
      />
    </>
  );
}

export default Sidebar;
