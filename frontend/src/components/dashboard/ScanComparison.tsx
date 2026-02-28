'use client';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { compareScans, getProjectScans } from '@/lib/api';
import { ArrowRight, CheckCircle, AlertCircle, Minus } from 'lucide-react';
import { severityBadgeColor } from '@/lib/utils';

interface ScanComparisonProps {
  projectId: string;
}

export default function ScanComparison({ projectId }: ScanComparisonProps) {
  const [scan1Id, setScan1Id] = useState('');
  const [scan2Id, setScan2Id] = useState('');

  const { data: scansData } = useQuery({
    queryKey: ['scans-list', projectId],
    queryFn: () => getProjectScans(projectId, 1).then(r => r.data),
  });

  const completedScans = (scansData?.scans || []).filter((s: any) => s.status === 'completed');

  const { data: comparison, isLoading } = useQuery({
    queryKey: ['comparison', projectId, scan1Id, scan2Id],
    queryFn: () => compareScans(projectId, scan1Id, scan2Id).then(r => r.data),
    enabled: !!scan1Id && !!scan2Id && scan1Id !== scan2Id,
  });

  return (
    <div className="bg-white rounded-2xl shadow-sm p-6">
      <h3 className="text-lg font-bold mb-4">Compare Scans</h3>

      {/* Scan Selectors */}
      <div className="flex items-center gap-3 mb-6">
        <select value={scan1Id} onChange={e => setScan1Id(e.target.value)}
          className="flex-1 px-3 py-2 border rounded-lg text-sm">
          <option value="">Select older scan...</option>
          {completedScans.map((s: any) => (
            <option key={s.id} value={s.id}>
              #{s.id.slice(0, 8)} — {new Date(s.created_at).toLocaleDateString()} (Score: {s.overall_risk_score})
            </option>
          ))}
        </select>
        <ArrowRight className="w-5 h-5 text-gray-400 flex-shrink-0" />
        <select value={scan2Id} onChange={e => setScan2Id(e.target.value)}
          className="flex-1 px-3 py-2 border rounded-lg text-sm">
          <option value="">Select newer scan...</option>
          {completedScans.map((s: any) => (
            <option key={s.id} value={s.id}>
              #{s.id.slice(0, 8)} — {new Date(s.created_at).toLocaleDateString()} (Score: {s.overall_risk_score})
            </option>
          ))}
        </select>
      </div>

      {/* Results */}
      {isLoading && <p className="text-center text-gray-400 py-8">Comparing...</p>}

      {comparison && (
        <div className="space-y-6">
          {/* Score Comparison */}
          <div className="grid grid-cols-3 gap-4 text-center">
            <div className="p-4 bg-gray-50 rounded-xl">
              <p className="text-2xl font-bold">{comparison.scan1.risk_score}</p>
              <p className="text-xs text-gray-500">Before</p>
            </div>
            <div className={`p-4 rounded-xl ${
              comparison.improvement.risk_change < 0 ? 'bg-green-50' :
              comparison.improvement.risk_change > 0 ? 'bg-red-50' : 'bg-gray-50'
            }`}>
              <p className={`text-2xl font-bold ${
                comparison.improvement.risk_change < 0 ? 'text-green-600' :
                comparison.improvement.risk_change > 0 ? 'text-red-600' : 'text-gray-600'
              }`}>
                {comparison.improvement.risk_change > 0 ? '+' : ''}{comparison.improvement.risk_change}
              </p>
              <p className="text-xs text-gray-500">Change</p>
            </div>
            <div className="p-4 bg-gray-50 rounded-xl">
              <p className="text-2xl font-bold">{comparison.scan2.risk_score}</p>
              <p className="text-xs text-gray-500">After</p>
            </div>
          </div>

          {/* Fixed / New Summary */}
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 bg-green-50 border border-green-200 rounded-xl text-center">
              <CheckCircle className="w-6 h-6 text-green-500 mx-auto mb-1" />
              <p className="text-xl font-bold text-green-700">{comparison.improvement.fixed_count}</p>
              <p className="text-xs text-green-600">Fixed</p>
            </div>
            <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-center">
              <AlertCircle className="w-6 h-6 text-red-500 mx-auto mb-1" />
              <p className="text-xl font-bold text-red-700">{comparison.improvement.new_count}</p>
              <p className="text-xs text-red-600">New Issues</p>
            </div>
            <div className="p-4 bg-gray-50 border border-gray-200 rounded-xl text-center">
              <Minus className="w-6 h-6 text-gray-400 mx-auto mb-1" />
              <p className="text-xl font-bold text-gray-600">{comparison.unchanged_count}</p>
              <p className="text-xs text-gray-500">Unchanged</p>
            </div>
          </div>

          {/* Fixed Vulnerabilities List */}
          {comparison.fixed_vulnerabilities.length > 0 && (
            <div>
              <h4 className="text-sm font-bold text-green-700 mb-2">✅ Fixed Vulnerabilities</h4>
              <div className="space-y-1">
                {comparison.fixed_vulnerabilities.map((v: any) => (
                  <div key={v.id} className="flex items-center gap-2 text-sm p-2 bg-green-50 rounded-lg">
                    <span className={`w-2 h-2 rounded-full ${severityBadgeColor(v.severity)}`} />
                    <span className="font-medium">{v.vulnerability_type.replace(/_/g, ' ')}</span>
                    <span className="text-gray-400">in {v.file_path}:{v.line_number}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* New Vulnerabilities List */}
          {comparison.new_vulnerabilities.length > 0 && (
            <div>
              <h4 className="text-sm font-bold text-red-700 mb-2">⚠️ New Vulnerabilities</h4>
              <div className="space-y-1">
                {comparison.new_vulnerabilities.map((v: any) => (
                  <div key={v.id} className="flex items-center gap-2 text-sm p-2 bg-red-50 rounded-lg">
                    <span className={`w-2 h-2 rounded-full ${severityBadgeColor(v.severity)}`} />
                    <span className="font-medium">{v.vulnerability_type.replace(/_/g, ' ')}</span>
                    <span className="text-gray-400">in {v.file_path}:{v.line_number}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {!scan1Id || !scan2Id ? (
        <p className="text-center text-gray-400 text-sm py-4">
          Select two completed scans to compare their results
        </p>
      ) : null}
    </div>
  );
}