import React, { useState } from 'react';
import { Card, Badge, Form, InputGroup, Button } from 'react-bootstrap';
import { FiSearch, FiFilter, FiAlertCircle, FiCheckCircle, FiExternalLink } from 'react-icons/fi';
import FindingDetail from './FindingDetail';

const SEVERITY_COLORS = {
  critical: 'danger',
  high: 'warning',
  medium: 'primary',
  low: 'info',
  info: 'secondary',
};

function FindingsPanel({ findings = [], onFindingUpdated }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedFinding, setSelectedFinding] = useState(null);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.cve_ids && f.cve_ids.some((cve) => cve.toLowerCase().includes(searchTerm.toLowerCase())));

    const matchesSeverity =
      severityFilter === 'all' || f.severity?.toLowerCase() === severityFilter.toLowerCase();

    const matchesStatus =
      statusFilter === 'all' || f.status?.toLowerCase() === statusFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="findings-panel">
      {/* Filters bar */}
      <div className="row g-2 mb-3">
        <div className="col-md-6">
          <InputGroup>
            <InputGroup.Text className="bg-dark border-secondary text-muted">
              <FiSearch />
            </InputGroup.Text>
            <Form.Control
              type="text"
              placeholder="Search findings by title, description, or CVE..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-dark text-light border-secondary"
            />
          </InputGroup>
        </div>

        <div className="col-md-3">
          <Form.Select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-dark text-light border-secondary"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </Form.Select>
        </div>

        <div className="col-md-3">
          <Form.Select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-dark text-light border-secondary"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False Positive</option>
            <option value="remediated">Remediated</option>
          </Form.Select>
        </div>
      </div>

      {/* Findings count indicator */}
      <div className="d-flex justify-content-between align-items-center mb-3 text-muted small">
        <span>
          Showing <b>{filteredFindings.length}</b> of <b>{findings.length}</b> findings
        </span>
      </div>

      {/* Findings list */}
      {filteredFindings.length === 0 ? (
        <Card className="bg-dark text-center p-4 border-secondary text-muted">
          <p className="mb-0">No security findings matching the active criteria.</p>
        </Card>
      ) : (
        <div className="d-flex flex-column gap-2">
          {filteredFindings.map((finding) => {
            const sevKey = (finding.severity || 'info').toLowerCase();
            const badgeVariant = SEVERITY_COLORS[sevKey] || 'secondary';

            return (
              <Card
                key={finding.id}
                className="bg-dark border-secondary finding-card cursor-pointer"
                style={{
                  borderLeft: `4px solid var(--bs-${badgeVariant})`,
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease',
                }}
                onClick={() => setSelectedFinding(finding)}
              >
                <Card.Body className="py-2 px-3">
                  <div className="d-flex justify-content-between align-items-start gap-2">
                    <div className="flex-grow-1">
                      <div className="d-flex align-items-center gap-2 mb-1 flex-wrap">
                        <Badge bg={badgeVariant} className="text-uppercase" style={{ fontSize: '0.7rem' }}>
                          {finding.severity || 'INFO'}
                        </Badge>
                        <span className="badge bg-secondary" style={{ fontSize: '0.7rem' }}>
                          {finding.found_by_tool?.toUpperCase() || 'AGENT'}
                        </span>
                        {finding.cvss_score && (
                          <span className="badge bg-black border border-secondary text-info" style={{ fontSize: '0.7rem' }}>
                            CVSS {finding.cvss_score.toFixed(1)}
                          </span>
                        )}
                        <h6 className="mb-0 text-light fs-6">{finding.title}</h6>
                      </div>

                      <p className="text-muted small mb-1 text-truncate" style={{ maxWidth: '650px' }}>
                        {finding.description || 'No description available.'}
                      </p>

                      {finding.cve_ids && finding.cve_ids.length > 0 && (
                        <div className="d-flex gap-1 flex-wrap">
                          {finding.cve_ids.slice(0, 3).map((cve, idx) => (
                            <span
                              key={idx}
                              className="badge bg-black border border-secondary text-muted"
                              style={{ fontSize: '0.65rem' }}
                            >
                              {cve}
                            </span>
                          ))}
                          {finding.cve_ids.length > 3 && (
                            <span className="text-muted small">+{finding.cve_ids.length - 3} more</span>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="text-end d-flex flex-column align-items-end">
                      <span className="badge bg-dark border border-secondary text-light small text-capitalize">
                        {finding.status?.replace('_', ' ') || 'open'}
                      </span>
                      <Button
                        variant="link"
                        size="sm"
                        className="text-info p-0 mt-2 text-decoration-none small d-flex align-items-center gap-1"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(finding);
                        }}
                      >
                        Inspect <FiExternalLink size={12} />
                      </Button>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            );
          })}
        </div>
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetail
          finding={selectedFinding}
          show={!!selectedFinding}
          onHide={() => setSelectedFinding(null)}
          onUpdate={(updated) => {
            setSelectedFinding(updated);
            if (onFindingUpdated) onFindingUpdated(updated);
          }}
        />
      )}
    </div>
  );
}

export default FindingsPanel;
