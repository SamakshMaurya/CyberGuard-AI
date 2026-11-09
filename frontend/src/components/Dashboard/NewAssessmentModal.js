import React, { useState } from 'react';
import { Modal, Form, Button, Alert, Spinner } from 'react-bootstrap';
import { FiPlus, FiTarget } from 'react-icons/fi';
import { createAssessment } from '../../services/api';

function NewAssessmentModal({ show, onHide, onCreated }) {
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    description: '',
    scope: '',
  });
  const [errors, setErrors] = useState({});
  const [submitError, setSubmitError] = useState('');
  const [loading, setLoading] = useState(false);

  const validateTarget = (target) => {
    if (!target.trim()) return 'Target is required';
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const urlRegex = /^(https?:\/\/)?([\w.-]+)(:\d+)?(\/.*)?$/i;
    const domainRegex = /^[\w.-]+\.[a-z]{2,}$/i;
    if (!ipRegex.test(target) && !urlRegex.test(target) && !domainRegex.test(target)) {
      return 'Invalid target format. Use an IP address, URL, or domain name.';
    }
    return '';
  };

  const validate = () => {
    const newErrors = {};
    if (!formData.name.trim()) newErrors.name = 'Assessment name is required';
    const targetError = validateTarget(formData.target);
    if (targetError) newErrors.target = targetError;
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors((prev) => ({ ...prev, [name]: '' }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitError('');
    if (!validate()) return;

    setLoading(true);
    try {
      const payload = {
        name: formData.name.trim(),
        target: formData.target.trim(),
        description: formData.description.trim() || undefined,
        scope: formData.scope.trim() || undefined,
      };
      const result = await createAssessment(payload);
      setFormData({ name: '', target: '', description: '', scope: '' });
      setErrors({});
      onCreated(result);
    } catch (err) {
      setSubmitError(err.message || 'Failed to create assessment. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setFormData({ name: '', target: '', description: '', scope: '' });
    setErrors({});
    setSubmitError('');
    onHide();
  };

  return (
    <Modal show={show} onHide={handleClose} centered size="lg">
      <Modal.Header closeButton>
        <Modal.Title style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
          <FiPlus style={{ color: '#00d4ff' }} /> New VAPT Assessment
        </Modal.Title>
      </Modal.Header>
      <Form onSubmit={handleSubmit}>
        <Modal.Body>
          {submitError && (
            <Alert variant="danger" onClose={() => setSubmitError('')} dismissible>
              {submitError}
            </Alert>
          )}

          <Form.Group className="mb-3">
            <Form.Label>Assessment Name *</Form.Label>
            <Form.Control
              type="text"
              name="name"
              value={formData.name}
              onChange={handleChange}
              placeholder="e.g., Production Web Application Assessment"
              isInvalid={!!errors.name}
              autoFocus
            />
            <Form.Control.Feedback type="invalid">{errors.name}</Form.Control.Feedback>
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>
              <FiTarget style={{ marginRight: 4 }} /> Target (IP / URL) *
            </Form.Label>
            <Form.Control
              type="text"
              name="target"
              value={formData.target}
              onChange={handleChange}
              placeholder="e.g., 192.168.1.100 or https://example.com"
              isInvalid={!!errors.target}
            />
            <Form.Control.Feedback type="invalid">{errors.target}</Form.Control.Feedback>
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>Description</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              name="description"
              value={formData.description}
              onChange={handleChange}
              placeholder="Describe the assessment objectives and context..."
            />
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>Scope Notes</Form.Label>
            <Form.Control
              as="textarea"
              rows={2}
              name="scope"
              value={formData.scope}
              onChange={handleChange}
              placeholder="Define what is in/out of scope for testing..."
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={loading}
            style={{
              background: 'linear-gradient(135deg, #00d4ff, #7c3aed)',
              border: 'none',
              fontWeight: 600,
            }}
          >
            {loading ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" /> Creating...
              </>
            ) : (
              <>
                <FiPlus className="me-1" /> Create Assessment
              </>
            )}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}

export default NewAssessmentModal;
