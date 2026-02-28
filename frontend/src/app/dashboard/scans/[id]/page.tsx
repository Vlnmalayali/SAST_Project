'use client';
import { useState } from 'react';
import { useParams } from 'next/navigation';
import { useQuery, useMutation } from '@tanstack/react-query';
import { getScan, getVulnerabilities, createReport, downloadReport } from '@/lib/api';
import toast from 'react-hot-toast';
import { severityBadgeColor } from '@/lib/utils';
import { FileDown, ChevronDown, ChevronUp, RefreshCw } from 'lucide-react';
import SandboxTestPanel from '@/components/scans/SandboxTestPanel';

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => getScan(id).then(r => r.data),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'running' || status === 'queued' ? 3000 : false;
    },
  });

  const { data: vulnsData } = useQuery({
    queryKey: ['vulnerabilities', id, severityFilter],
    queryFn: () => getVulnerabilities(id, {
      severity: severityFilter !== 'all' ? severityFilter : undefined,
      limit: 100,
    }).then(r => r.data),
    enabled: scan?.status === 'completed',
  });

  const reportMutation = useMutation({
    mutationFn: async () => {
      const { data: report } = await createReport(id);
      const blob = await downloadReport(report.id);
      const url = window.URL.createObjectURL(new Blob([blob.data]));
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-report-${id.slice(0, 8)}.pdf`;
      link.click();
      window.URL.revokeObjectURL(url);
    },
    onSuccess: () => toast.success('Report downloaded!'),
    onError: () => toast.error('Report generation failed'),
  });

  if (scanLoading) return <div className="text-center py-20 text-gray-400">Loading scan...</div>;
  if (!scan) return <div className="text-center py-20 text-red-500">Scan not found</div>;

  const vulns = vulnsData?.vulnerabilities || [];

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Scan #{id.slice(0, 8)}</h1>
          <div className="flex items-center gap-3 mt-1 text-sm text-gray-500">
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium text-white ${
              scan.status === 'completed' ? 'bg-green-500' :
              scan.status === 'running' ? 'bg-blue-500' :
              scan.status === 'failed' ? 'bg-red-500' : 'bg-gray-400'
            }`}>{scan.status}</span>
            <span>{new Date(scan.created_at).toLocaleString()}</span>
            {scan.scan_duration_seconds && <span>{scan.scan_duration_seconds}s</span>}
          </div>
        </div>

        {scan.status === 'completed' && (
          <button onClick={() => reportMutation.mutate()}
            disabled={reportMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50">
            <FileDown className="w-5 h-5" />
            {reportMutation.isPending ? 'Generating...' : 'Download Report'}
          </button>
        )}
      </div>

      {/* Running / Queued State */}
      {(scan.status === 'running' || scan.status === 'queued') && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-8 text-center mb-8">
          <RefreshCw className="w-10 h-10 text-blue-500 mx-auto mb-3 animate-spin" />
          <p className="text-lg font-medium text-blue-700">
            {scan.status === 'running' ? 'Scan in progress...' : 'Scan queued...'}
          </p>
          <p className="text-sm text-blue-500 mt-1">This page will auto-refresh.</p>
        </div>
      )}

      {/* Stats Cards */}
      {scan.status === 'completed' && (
        <>
          <div className="grid md:grid-cols-5 gap-4 mb-8">
            <div className="bg-white rounded-xl shadow-sm p-5 text-center">
              <p className={`text-3xl font-bold ${
                scan.overall_risk_score >= 8 ? 'text-red-600' :
                scan.overall_risk_score >= 6 ? 'text-orange-600' :
                scan.overall_risk_score >= 4 ? 'text-yellow-600' : 'text-green-600'
              }`}>{scan.overall_risk_score}</p>
              <p className="text-sm text-gray-500">Risk Score</p>
            </div>
            <div className="bg-white rounded-xl shadow-sm p-5 text-center">
              <p className="text-3xl font-bold text-red-600">{scan.critical_count}</p>
              <p className="text-sm text-gray-500">Critical</p>
            </div>
            <div className="bg-white rounded-xl shadow-sm p-5 text-center">
              <p className="text-3xl font-bold text-orange-500">{scan.high_count}</p>
              <p className="text-sm text-gray-500">High</p>
            </div>
            <div className="bg-white rounded-xl shadow-sm p-5 text-center">
              <p className="text-3xl font-bold text-yellow-500">{scan.medium_count}</p>
              <p className="text-sm text-gray-500">Medium</p>
            </div>
            <div className="bg-white rounded-xl shadow-sm p-5 text-center">
              <p className="text-3xl font-bold text-green-500">{scan.low_count}</p>
              <p className="text-sm text-gray-500">Low</p>
            </div>
          </div>

          {/* Severity Filter */}
          <div className="flex gap-2 mb-6">
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button key={sev} onClick={() => setSeverityFilter(sev)}
                className={`px-4 py-1.5 rounded-full text-sm font-medium transition ${
                  severityFilter === sev
                    ? 'bg-primary-600 text-white'
                    : 'bg-white border text-gray-600 hover:bg-gray-50'
                }`}>
                {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>

          {/* Vulnerability List */}
          <div className="space-y-3">
            {vulns.length === 0 ? (
              <div className="bg-green-50 border border-green-200 rounded-xl p-8 text-center">
                <p className="text-lg font-medium text-green-700">🎉 No vulnerabilities found!</p>
              </div>
            ) : (
              vulns.map((vuln: any) => (
                <div key={vuln.id} className="bg-white rounded-xl shadow-sm border overflow-hidden">
                  {/* Vuln Header */}
                  <button
                    onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                    className="w-full flex items-center justify-between p-4 hover:bg-gray-50 transition text-left"
                  >
                    <div className="flex items-center gap-3">
                      <span className={`w-2.5 h-2.5 rounded-full ${severityBadgeColor(vuln.severity)}`} />
                      <div>
                        <p className="font-medium">
                          {vuln.vulnerability_type.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                        </p>
                        <p className="text-sm text-gray-500">
                          {vuln.file_path}:{vuln.line_number}
                          {vuln.cwe_id && <span className="ml-2 text-blue-500">{vuln.cwe_id}</span>}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold text-white ${severityBadgeColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className="text-sm text-gray-500">CVSS {vuln.cvss_score}</span>
                      {expandedVuln === vuln.id ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                    </div>
                  </button>

                  {/* Expanded Details */}
                  {expandedVuln === vuln.id && (
                    <div className="border-t px-6 py-5 space-y-4 bg-gray-50">
                      {/* Code Snippet */}
                      <div>
                        <h4 className="text-sm font-bold text-gray-700 mb-2">Vulnerable Code</h4>
                        <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm overflow-x-auto whitespace-pre">
                          {vuln.code_snippet}
                        </pre>
                      </div>

                      {/* AI Explanation */}
                      {vuln.ai_explanation && (
                        <div>
                          <h4 className="text-sm font-bold text-gray-700 mb-2">🤖 AI Analysis</h4>
                          <p className="text-sm text-gray-600 bg-white p-4 rounded-lg border">{vuln.ai_explanation}</p>
                        </div>
                      )}

                      {/* Fix */}
                      {vuln.ai_fixed_code && (
                        <div>
                          <h4 className="text-sm font-bold text-gray-700 mb-2">✅ Suggested Fix</h4>
                          <pre className="bg-green-900 text-green-100 p-4 rounded-lg text-sm overflow-x-auto whitespace-pre">
                            {vuln.ai_fixed_code}
                          </pre>
                        </div>
                      )}

                      {/* Remediation */}
                      {vuln.remediation_steps?.remediation_steps && (
                        <div>
                          <h4 className="text-sm font-bold text-gray-700 mb-2">📋 Remediation Steps</h4>
                          <ol className="list-decimal list-inside space-y-1 text-sm text-gray-600 bg-white p-4 rounded-lg border">
                            {vuln.remediation_steps.remediation_steps.map((step: string, i: number) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ol>
                        </div>
                      )}

                      <div className="flex items-center gap-4 text-xs text-gray-400 pt-2">
                        <span>Confidence: {(vuln.confidence * 100).toFixed(0)}%</span>
                        {vuln.is_false_positive && <span className="text-orange-500 font-medium">Marked as False Positive</span>}
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {/* Sandbox Testing */}
          <div className="mt-8">
            <SandboxTestPanel scanId={id} />
          </div>
        </>
      )}
    </div>
  );
}