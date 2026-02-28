import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth
export const register = (data: { email: string; password: string; full_name: string }) =>
  api.post('/auth/register', data);

export const login = (data: { email: string; password: string }) =>
  api.post('/auth/login', data);

export const getMe = () => api.get('/auth/me');

// Projects
export const getProjects = (page = 1) => api.get(`/projects?page=${page}`);
export const createProject = (data: Record<string, unknown>) => api.post('/projects', data);
export const getProject = (id: string) => api.get(`/projects/${id}`);
export const deleteProject = (id: string) => api.delete(`/projects/${id}`);

// Scans
export const createScan = (projectId: string, formData: FormData) =>
  api.post(`/projects/${projectId}/scans`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });

export const createScanFromSource = (projectId: string, sourceCode: string) => {
  const formData = new FormData();
  formData.append('source_code', sourceCode);
  return api.post(`/projects/${projectId}/scans`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};

export const getScan = (scanId: string) => api.get(`/scans/${scanId}`);
export const getScanStatus = (scanId: string) => api.get(`/scans/${scanId}/status`);
export const getProjectScans = (projectId: string, page = 1) =>
  api.get(`/projects/${projectId}/scans?page=${page}`);

// Vulnerabilities
export const getVulnerabilities = (scanId: string, params?: Record<string, unknown>) =>
  api.get(`/scans/${scanId}/vulnerabilities`, { params });
export const getVulnerability = (id: string) => api.get(`/vulnerabilities/${id}`);
export const markFalsePositive = (id: string, reason: string) =>
  api.patch(`/vulnerabilities/${id}`, { is_false_positive: true, false_positive_reason: reason });
export const regenerateFix = (id: string) => api.post(`/vulnerabilities/${id}/regenerate-fix`);

// Reports
export const createReport = (scanId: string) => api.post(`/scans/${scanId}/reports`);
export const downloadReport = (reportId: string) =>
  api.get(`/reports/${reportId}/download`, { responseType: 'blob' });

// Analytics
export const getRiskTrend = (projectId: string) =>
  api.get('/analytics/risk-trend', { params: { project_id: projectId } });
export const getVulnDistribution = (projectId: string) =>
  api.get('/analytics/vulnerability-distribution', { params: { project_id: projectId } });
export const getSeverityDistribution = (projectId: string) =>
  api.get('/analytics/severity-distribution', { params: { project_id: projectId } });
export const getProjectSummary = (projectId: string) =>
  api.get('/analytics/summary', { params: { project_id: projectId } });

// GitHub
export const getGithubOAuth = () => api.get('/github/oauth');
export const getGithubRepos = () => api.get('/github/repos');
export const triggerGithubScan = (data: Record<string, unknown>) => api.post('/github/scan', data);

// Sandbox
export const getSandboxStatus = () => api.get('/sandbox/status');
export const runSandboxTest = (scanId: string) => api.post(`/sandbox/test/${scanId}`);

// Comparison
export const compareScans = (projectId: string, scan1: string, scan2: string) =>
  api.get('/analytics/comparison', { params: { project_id: projectId, scan1, scan2 } });

export default api;