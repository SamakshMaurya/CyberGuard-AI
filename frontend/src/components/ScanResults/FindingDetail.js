import React, { useState } from 'react';
import { Modal, Button, Badge, Form, Alert } from 'react-bootstrap';
import { FiAlertTriangle, FiCheck, FiX, FiShield, FiExternalLink } from 'react-icons/fi';
import { updateFinding } from '../../services/api';

const SEVERITY_COLORS = {
  critical: 'danger',
  high: 'warning',
  medium: 'primary',
  low: 'info',
  info: 'secondary',
};

function FindingDetail({ finding, show, onHide, onUpdate }) {
  const [status, setStatus] = useState(finding?.status || 'open');
  const [remediationNotes, setRemediationNotes] = useState(finding?.remediation || '');
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  if (!finding) return null;

  const handleSave = async () => {
    setIsSaving(true);
    setErrorMsg('');
    try {
      const updated = await updateFinding(finding.id, {
        status: status,
        remediation: remediationNotes,
      });
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2500);
      if (onUpdate) onUpdate(updated);
    } catch (err) {
      console.error('Failed to update finding:', err);
      setErrorMsg('Failed to update finding. Please try again.');
    } finally {
      setIsSaving(false);
    }
  };

  const sevColor = SEVERITY_COLORS[finding.severity?.toLowerCase()] || 'secondary';

  return (
    <Modal show={show} onHide={onHide} size="lg" centered className="cyber-modal">
      <Modal.Header closeButton className="border-secondary bg-dark text-light">
        <Modal.Title className="d-flex align-items-center gap-2">
          <Badge bg={sevColor} className="text-uppercase">
            {finding.severity || 'INFO'}
          </Badge>
          <span className="fs-5">{finding.title}</span>
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="bg-dark text-light">
        {saveSuccess && (
          <Alert variant="success" className="py-2">
            Finding updated successfully.
          </Alert>
        )}
        {errorMsg && (
          <Alert variant="danger" className="py-2">
            {errorMsg}
          </Alert>
        )}

        {/* Metadata row */}
        <div className="d-flex flex-wrap gap-3 mb-4 p-3 rounded border border-secondary bg-black bg-opacity-25">
          <div>
            <small className="text-muted d-block">Originating Tool</small>
            <span className="badge bg-secondary text-uppercase">{finding.found_by_tool || 'AI Agent'}</span>
          </div>

          <div>
            <small className="text-muted d-block">CVSS Score</small>
            <span className={`fw-bold text-${sevColor}`}>
              {finding.cvss_score !== null && finding.cvss_score !== undefined
                ? finding.cvss_score.toFixed(1)
                : 'N/A'}
            </span>
          </div>

          <div>
            <small className="text-muted d-block">Current Status</small>
            <span className="text-capitalize">{status.replace('_', ' ')}</span>
          </div>

          {finding.cve_ids && finding.cve_ids.length > 0 && (
            <div>
              <small className="text-muted d-block">Associated CVEs</small>
              <div className="d-flex gap-1 flex-wrap">
                {finding.cve_ids.map((cve, idx) => (
                  <span key={idx} className="badge bg-dark border border-secondary text-info">
                    {cve}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Description */}
        <div className="mb-4">
          <h6 className="text-info d-flex align-items-center gap-2">
            <FiShield /> Description
          </h6>
          <p className="text-light bg-black bg-opacity-25 p-3 rounded border border-secondary">
            {finding.description || 'No description provided.'}
          </p>
        </div>

        {/* Evidence */}
        {finding.evidence && (
          <div className="mb-4">
            <h6 className="text-warning d-flex align-items-center gap-2">
              <FiAlertTriangle /> Technical Evidence & Output
            </h6>
            <pre className="p-3 bg-black rounded border border-secondary text-success font-monospace small text-wrap">
              {finding.evidence}
            </pre>
          </div>
        )}

        {/* Remediation & Status Edit */}
        <div className="mb-3">
          <h6 className="text-success d-flex align-items-center gap-2">
            <FiCheck /> Recommended Remediation & Action Plan
          </h6>
          <Form.Group className="mb-3">
            <Form.Control
              as="textarea"
              rows={4}
              value={remediationNotes}
              onChange={(e) => setRemediationNotes(e.target.value)}
              className="bg-black text-light border-secondary font-monospace small"
              placeholder="Recommended fix or technical remediation details..."
            />
          </Form.Group>

          <Form.Group>
            <Form.Label className="small text-muted">Update Triage Status:</Form.Label>
            <Form.Select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="bg-dark text-light border-secondary"
            >
              <option value="open">Open (Unverified)</option>
              <option value="confirmed">Confirmed Vulnerability</option>
              <option value="false_positive">False Positive</option>
              <option value="remediated">Remediated / Verified Fixed</option>
            </Form.Select>
          </Form.Group>
        </div>
      </Modal.Body>

      <Modal.Footer className="border-secondary bg-dark">
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
        <Button variant="info" onClick={handleSave} disabled={isSaving}>
          {isSaving ? 'Saving...' : 'Save Changes'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default FindingDetail;
