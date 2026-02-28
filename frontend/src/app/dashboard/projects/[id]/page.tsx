'use client';
import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getProject, getProjectScans } from '@/lib/api';
import Link from 'next/link';
import { Play, Clock, ArrowRight } from 'lucide-react';
import FileUploadScanner from '@/components/scans/FileUploadScanner';
import ScanComparison from '@/components/dashboard/ScanComparison';

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [showScan, setShowScan] = useState(false);

  const { data: project, isLoading: projectLoading } = useQuery({
    queryKey: ['project', id],
    queryFn: () => getProject(id).then(r => r.data),
  });

  const { data: scansData } = useQuery({
    queryKey: ['scans', id],
    queryFn: () => getProjectScans(id).then(r => r.data),
  });

  if (projectLoading) return <div className="text-center py-20 text-gray-400">Loading...</div>;
  if (!project) return <div className="text-center py-20 text-red-500">Project not found</div>;

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">{project.name}</h1>
          <p className="text-gray-500 mt-1">{project.description || 'No description'}</p>
          <div className="flex items-center gap-3 mt-2">
            <span className="bg-blue-100 text-blue-700 px-2 py-0.5 rounded text-xs font-medium">
              {project.language}
            </span>
            {project.latest_risk_score !== null && (
              <span className={`text-sm font-bold ${
                project.latest_risk_score >= 7 ? 'text-red-600' :
                project.latest_risk_score >= 4 ? 'text-yellow-600' : 'text-green-600'
              }`}>
                Risk: {project.latest_risk_score}/10
              </span>
            )}
          </div>
        </div>
        <button onClick={() => setShowScan(true)}
          className="flex items-center gap-2 px-5 py-2.5 bg-primary-600 text-white rounded-xl hover:bg-primary-700 font-medium">
          <Play className="w-5 h-5" /> New Scan
        </button>
      </div>

      {/* File Upload Scanner Modal */}
      {showScan && (
        <FileUploadScanner
          projectId={id}
          onScanStarted={(scanId) => {
            setShowScan(false);
            queryClient.invalidateQueries({ queryKey: ['scans', id] });
            router.push(`/dashboard/scans/${scanId}`);
          }}
          onClose={() => setShowScan(false)}
        />
      )}

      {/* Scan History */}
      <div className="bg-white rounded-2xl shadow-sm p-6 mb-8">
        <h2 className="text-lg font-bold mb-4">Scan History</h2>
        {!scansData?.scans?.length ? (
          <p className="text-gray-400 text-center py-8">No scans yet. Click "New Scan" to get started.</p>
        ) : (
          <div className="space-y-3">
            {scansData.scans.map((scan: any) => (
              <Link key={scan.id} href={`/dashboard/scans/${scan.id}`}
                className="flex items-center justify-between p-4 border rounded-xl hover:bg-gray-50 transition group">
                <div className="flex items-center gap-4">
                  <div className={`w-3 h-3 rounded-full flex-shrink-0 ${
                    scan.status === 'completed' ? 'bg-green-500' :
                    scan.status === 'running' ? 'bg-blue-500 animate-pulse' :
                    scan.status === 'failed' ? 'bg-red-500' : 'bg-gray-400'
                  }`} />
                  <div>
                    <p className="font-medium">Scan #{scan.id.slice(0, 8)}</p>
                    <div className="flex items-center gap-3 text-sm text-gray-500">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                      <span className="capitalize">{scan.status}</span>
                      {scan.total_files_scanned > 0 && (
                        <span>{scan.total_files_scanned} files · {scan.total_lines_scanned.toLocaleString()} lines</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {scan.status === 'completed' && (
                    <>
                      <div className="flex gap-1.5">
                        {scan.critical_count > 0 && (
                          <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded-full text-xs font-medium">
                            {scan.critical_count}C
                          </span>
                        )}
                        {scan.high_count > 0 && (
                          <span className="bg-orange-100 text-orange-700 px-2 py-0.5 rounded-full text-xs font-medium">
                            {scan.high_count}H
                          </span>
                        )}
                        {scan.medium_count > 0 && (
                          <span className="bg-yellow-100 text-yellow-700 px-2 py-0.5 rounded-full text-xs font-medium">
                            {scan.medium_count}M
                          </span>
                        )}
                        {scan.low_count > 0 && (
                          <span className="bg-green-100 text-green-700 px-2 py-0.5 rounded-full text-xs font-medium">
                            {scan.low_count}L
                          </span>
                        )}
                      </div>
                      <span className={`px-3 py-1 rounded-full text-sm font-bold text-white ${
                        scan.overall_risk_score >= 8 ? 'bg-red-500' :
                        scan.overall_risk_score >= 6 ? 'bg-orange-500' :
                        scan.overall_risk_score >= 4 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}>
                        {scan.overall_risk_score}
                      </span>
                    </>
                  )}
                  <ArrowRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500 transition" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>

      {/* Scan Comparison */}
      {(scansData?.scans?.length || 0) >= 2 && (
        <ScanComparison projectId={id} />
      )}
    </div>
  );
}