import React from 'react';
import { FiAlertTriangle, FiCheck, FiX } from 'react-icons/fi';

function ApprovalCard({ data, responded, approvedValue, onApprove, onDeny }) {
  const actionId = data?.action_id || '';
  const description = data?.description || 'An action requires your approval.';
  const risk = data?.risk || 'Unknown';

  const riskColors = {
    low: '#3b82f6',
    medium: '#f59e0b',
    high: '#f97316',
    critical: '#ef4444',
  };

  const riskColor = riskColors[risk.toLowerCase()] || '#f59e0b';

  return (
    <div className="approval-request">
      <div className="approval-header">
        <FiAlertTriangle style={{ fontSize: '1.1rem' }} />
        ⚠️ Human Approval Required
      </div>

      <div className="approval-description">{description}</div>

      <div className="approval-risk" style={{ borderLeft: `3px solid ${riskColor}` }}>
        Risk Level: <strong style={{ color: riskColor }}>{risk.toUpperCase()}</strong>
      </div>

      {!responded ? (
        <div className="approval-actions">
          <button className="approval-btn approve" onClick={() => onApprove(actionId)}>
            <FiCheck style={{ marginRight: 4 }} /> Approve
          </button>
          <button className="approval-btn deny" onClick={() => onDeny(actionId)}>
            <FiX style={{ marginRight: 4 }} /> Deny
          </button>
        </div>
      ) : (
        <div>
          <span className={`approval-status ${approvedValue ? 'approved' : 'denied'}`}>
            {approvedValue ? (
              <>
                <FiCheck style={{ marginRight: 4 }} /> Approved
              </>
            ) : (
              <>
                <FiX style={{ marginRight: 4 }} /> Denied
              </>
            )}
          </span>
        </div>
      )}
    </div>
  );
}

export default React.memo(ApprovalCard);
