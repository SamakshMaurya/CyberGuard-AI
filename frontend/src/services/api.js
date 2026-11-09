import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';
const WS_BASE = 'ws://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message = error.response?.data?.detail || error.message || 'An unexpected error occurred';
    console.error('API Error:', message);
    return Promise.reject({ message, status: error.response?.status });
  }
);

/* ========================
   Assessment CRUD
   ======================== */

export const createAssessment = async (data) => {
  const response = await apiClient.post('/assessments', data);
  return response.data;
};

export const getAssessments = async () => {
  const response = await apiClient.get('/assessments');
  return response.data;
};

export const getAssessment = async (id) => {
  const response = await apiClient.get(`/assessments/${id}`);
  return response.data;
};

export const deleteAssessment = async (id) => {
  const response = await apiClient.delete(`/assessments/${id}`);
  return response.data;
};

/* ========================
   Chat
   ======================== */

export const getChatHistory = async (assessmentId) => {
  const response = await apiClient.get(`/assessments/${assessmentId}/chat`);
  return response.data;
};

export const sendMessage = async (assessmentId, message) => {
  const response = await apiClient.post(`/assessments/${assessmentId}/chat`, { message });
  return response.data;
};

export const createChatWebSocket = (assessmentId) => {
  const wsUrl = `${WS_BASE}/assessments/${assessmentId}/chat/ws`;
  const ws = new WebSocket(wsUrl);
  return ws;
};

/* ========================
   Scans
   ======================== */

export const getScans = async (assessmentId) => {
  const response = await apiClient.get(`/assessments/${assessmentId}/scans`);
  return response.data;
};

export const getScanResult = async (scanId) => {
  const response = await apiClient.get(`/scans/${scanId}`);
  return response.data;
};

export const getFindings = async (assessmentId, severity = null) => {
  const params = {};
  if (severity) params.severity = severity;
  const response = await apiClient.get(`/assessments/${assessmentId}/findings`, { params });
  return response.data;
};

export const updateFinding = async (findingId, data) => {
  const response = await apiClient.patch(`/findings/${findingId}`, data);
  return response.data;
};

export const approveAction = async (assessmentId, actionId, approved) => {
  const response = await apiClient.post(`/assessments/${assessmentId}/approve`, {
    action_id: actionId,
    approved,
  });
  return response.data;
};

/* ========================
   Reports
   ======================== */

export const generateReport = async (assessmentId) => {
  const response = await apiClient.post(`/assessments/${assessmentId}/reports`);
  return response.data;
};

export const getReports = async (assessmentId) => {
  const response = await apiClient.get(`/assessments/${assessmentId}/reports`);
  return response.data;
};

export const downloadReport = async (reportId) => {
  const response = await apiClient.get(`/reports/${reportId}/download`, {
    responseType: 'blob',
  });
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;
  const contentDisposition = response.headers['content-disposition'];
  let fileName = `report-${reportId}.pdf`;
  if (contentDisposition) {
    const match = contentDisposition.match(/filename="?(.+)"?/);
    if (match) fileName = match[1];
  }
  link.setAttribute('download', fileName);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

export default apiClient;
