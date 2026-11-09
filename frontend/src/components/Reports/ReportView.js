import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Card, Button, Badge, Spinner, Alert } from 'react-bootstrap';
import {
  FiFileText,
  FiDownload,
  FiArrowLeft,
  FiShield,
  FiCalendar,
  FiCheckCircle,
  FiAlertTriangle,
} from 'react-icons/fi';
import {
  getAssessment,
  getReports,
  generateReport,
  downloadReport,
  getFindings,
} from '../../services/api';

function ReportView() {
  const { id } = useParams();

  const [assessment, setAssessment] = useState(null);
  const [reports, setReports] = useState([]);
  const [findings, setFindings] = useState([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const loadData = useCallback(async () => {
    try {
      const [assessmentData, reportsData, findingsData] = await Promise.all([
        getAssessment(id),
        getReports(id),
        getFindings(id),
      ]);
      setAssessment(assessmentData);
      setReports(Array.isArray(reportsData) ? reportsData : reportsData.reports || []);
      setFindings(Array.isArray(findingsData) ? findingsData : findingsData.findings || []);
    } catch (err) {
      console.error('Failed to load report view data:', err);
      setErrorMsg('Failed to fetch assessment reports data.');
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const newReport = await generateReport(id);
      setSuccessMsg('VAPT PDF Report generated successfully!');
      setReports((prev) => [newReport, ...prev]);
    } catch (err) {
      console.error('Failed to generate report:', err);
      setErrorMsg('Failed to generate PDF report. Check server logs.');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownload = async (reportId, filename) => {
    try {
      await downloadReport(reportId, filename || `CyberGuard_Report_${id}.pdf`);
    } catch (err) {
      console.error('Download failed:', err);
      setErrorMsg('Failed to download report PDF.');
    }
  };

  const criticalCount = findings.filter((f) => f.severity?.toLowerCase() === 'critical').length;
  const highCount = findings.filter((f) => f.severity?.toLowerCase() === 'high').length;
  const mediumCount = findings.filter((f) => f.severity?.toLowerCase() === 'medium').length;

  return (
    <div className="container-fluid p-4">
      {/* Top Header */}
      <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div className="d-flex align-items-center gap-3">
          <Link to={`/assessment/${id}`} className="btn btn-outline-secondary btn-sm d-flex align-items-center gap-1">
            <FiArrowLeft /> Back to Assessment Chat
          </Link>
          <div>
            <h4 className="mb-0 text-light d-flex align-items-center gap-2">
              <FiFileText className="text-info" /> VAPT Assessment Deliverables
            </h4>
            <small className="text-muted">
              Target: <code className="text-info">{assessment?.target || 'Loading...'}</code> | Assessment #{id}
            </small>
          </div>
        </div>

        <Button
          variant="info"
          className="d-flex align-items-center gap-2 fw-semibold"
          onClick={handleGenerateReport}
          disabled={isGenerating}
        >
          {isGenerating ? (
            <>
              <Spinner animation="border" size="sm" />
              Generating PDF Report...
            </>
          ) : (
            <>
              <FiFileText />
              Generate Client-Ready PDF
            </>
          )}
        </Button>
      </div>

      {errorMsg && <Alert variant="danger" dismissible onClose={() => setErrorMsg('')}>{errorMsg}</Alert>}
      {successMsg && <Alert variant="success" dismissible onClose={() => setSuccessMsg('')}>{successMsg}</Alert>}

      {/* Overview Cards */}
      <div className="row g-3 mb-4">
        <div className="col-md-3">
          <Card className="bg-dark border-secondary h-100">
            <Card.Body>
              <div className="text-muted small text-uppercase">Assessment Scope</div>
              <div className="fs-5 text-light fw-bold text-truncate">{assessment?.target}</div>
              <small className="text-info">{assessment?.scope || 'Authorized Laboratory Target'}</small>
            </Card.Body>
          </Card>
        </div>

        <div className="col-md-3">
          <Card className="bg-dark border-secondary h-100">
            <Card.Body>
              <div className="text-muted small text-uppercase">Total Findings</div>
              <div className="fs-3 text-light fw-bold">{findings.length}</div>
              <div className="d-flex gap-2 mt-1">
                <span className="badge bg-danger">{criticalCount} Critical</span>
                <span className="badge bg-warning text-dark">{highCount} High</span>
                <span className="badge bg-primary">{mediumCount} Med</span>
              </div>
            </Card.Body>
          </Card>
        </div>

        <div className="col-md-3">
          <Card className="bg-dark border-secondary h-100">
            <Card.Body>
              <div className="text-muted small text-uppercase">PDF Deliverables</div>
              <div className="fs-3 text-light fw-bold">{reports.length}</div>
              <small className="text-muted">ReportLab Engine Version 4.0</small>
            </Card.Body>
          </Card>
        </div>

        <div className="col-md-3">
          <Card className="bg-dark border-secondary h-100">
            <Card.Body>
              <div className="text-muted small text-uppercase">Assessment Status</div>
              <div className="fs-5 text-success fw-bold text-uppercase mt-1">
                {assessment?.status || 'Active'}
              </div>
              <small className="text-muted">Strict Sandbox Gated Policy</small>
            </Card.Body>
          </Card>
        </div>
      </div>

      {/* Reports List */}
      <div className="row">
        <div className="col-12">
          <Card className="bg-dark border-secondary">
            <Card.Header className="bg-dark border-secondary text-light d-flex justify-content-between align-items-center">
              <span className="fw-semibold d-flex align-items-center gap-2">
                <FiShield className="text-info" /> Generated Assessment Documents
              </span>
              <span className="badge bg-secondary">{reports.length} available</span>
            </Card.Header>

            <Card.Body>
              {reports.length === 0 ? (
                <div className="text-center py-5 text-muted">
                  <FiFileText size={48} className="mb-3 text-secondary" />
                  <h5>No Reports Generated Yet</h5>
                  <p className="small mb-3">
                    Click "Generate Client-Ready PDF" above to produce a complete VAPT executive summary,
                    methodology breakdown, and remediation roadmap.
                  </p>
                  <Button variant="outline-info" size="sm" onClick={handleGenerateReport} disabled={isGenerating}>
                    Generate Initial Report
                  </Button>
                </div>
              ) : (
                <div className="d-flex flex-column gap-3">
                  {reports.map((report) => (
                    <Card key={report.id} className="bg-black bg-opacity-50 border-secondary">
                      <Card.Body className="d-flex justify-content-between align-items-center flex-wrap gap-3">
                        <div className="flex-grow-1">
                          <div className="d-flex align-items-center gap-2 mb-1">
                            <span className="badge bg-info text-dark">PDF</span>
                            <h6 className="mb-0 text-light">{report.title}</h6>
                          </div>

                          <div className="text-muted small d-flex align-items-center gap-3 mb-2">
                            <span>
                              <FiCalendar className="me-1" />
                              {new Date(report.created_at).toLocaleString()}
                            </span>
                            <span>ID: #{report.id}</span>
                          </div>

                          {report.executive_summary && (
                            <p className="text-light small bg-dark p-2 rounded border border-secondary mb-0">
                              {report.executive_summary}
                            </p>
                          )}
                        </div>

                        <div>
                          <Button
                            variant="success"
                            className="d-flex align-items-center gap-2"
                            onClick={() => handleDownload(report.id, `CyberGuard_Report_${report.id}.pdf`)}
                          >
                            <FiDownload /> Download PDF
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  ))}
                </div>
              )}
            </Card.Body>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default ReportView;
