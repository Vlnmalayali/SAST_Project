'use client';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getProjects, getRiskTrend, getVulnDistribution, getSeverityDistribution, getProjectSummary } from '@/lib/api';
import Link from 'next/link';
import { Shield, FolderOpen, AlertTriangle, TrendingDown } from 'lucide-react';
import RiskScoreCard from '@/components/dashboard/RiskScoreCard';
import VulnerabilityChart from '@/components/dashboard/VulnerabilityChart';
import SeverityBarChart from '@/components/dashboard/SeverityBarChart';
import TrendGraph from '@/components/dashboard/TrendGraph';
import ImprovementCard from '@/components/dashboard/ImprovementCard';

export default function DashboardPage() {
  const { data: projectsData } = useQuery({
    queryKey: ['projects'],
    queryFn: () => getProjects().then(r => r.data),
  });

  const projects = projectsData?.projects || [];
  const activeProject = projects[0]; // Most recent

  const { data: trendData } = useQuery({
    queryKey: ['risk-trend', activeProject?.id],
    queryFn: () => getRiskTrend(activeProject.id).then(r => r.data),
    enabled: !!activeProject,
  });

  const { data: vulnDistData } = useQuery({
    queryKey: ['vuln-dist', activeProject?.id],
    queryFn: () => getVulnDistribution(activeProject.id).then(r => r.data),
    enabled: !!activeProject,
  });

  const { data: sevDistData } = useQuery({
    queryKey: ['sev-dist', activeProject?.id],
    queryFn: () => getSeverityDistribution(activeProject.id).then(r => r.data),
    enabled: !!activeProject,
  });

  const { data: summaryData } = useQuery({
    queryKey: ['summary', activeProject?.id],
    queryFn: () => getProjectSummary(activeProject.id).then(r => r.data),
    enabled: !!activeProject,
  });

  const totalScans = projects.reduce((sum: number, p: any) => sum + (p.scan_count || 0), 0);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Dashboard</h1>

      {/* Top Stats */}
      <div className="grid md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Projects', value: projects.length, icon: FolderOpen, color: 'bg-blue-500' },
          { label: 'Total Scans', value: totalScans, icon: Shield, color: 'bg-purple-500' },
          { label: 'Active Issues', value: summaryData?.latest_vulnerability_count ?? '—', icon: AlertTriangle, color: 'bg-orange-500' },
          { label: 'Improvement', value: summaryData?.risk_improvement_percentage !== null ? `${summaryData?.risk_improvement_percentage}%` : '—', icon: TrendingDown, color: 'bg-green-500' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-white rounded-xl shadow-sm p-6 flex items-center gap-4">
            <div className={`${color} p-3 rounded-lg`}>
              <Icon className="w-6 h-6 text-white" />
            </div>
            <div>
              <p className="text-2xl font-bold">{value}</p>
              <p className="text-sm text-gray-500">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Section */}
      {activeProject ? (
        <>
          {/* Project Selector */}
          <div className="flex items-center gap-2 mb-6 text-sm text-gray-500">
            <span>Showing analytics for:</span>
            <span className="font-semibold text-gray-900">{activeProject.name}</span>
          </div>

          {/* Row 1: Risk Score + Trend */}
          <div className="grid md:grid-cols-2 gap-6 mb-6">
            <RiskScoreCard
              score={summaryData?.latest_risk_score ?? 0}
              previousScore={trendData?.data?.length > 1 ? trendData.data[trendData.data.length - 2]?.risk_score : null}
            />
            <ImprovementCard summary={summaryData || null} />
          </div>

          {/* Row 2: Trend Graph */}
          <div className="mb-6">
            <TrendGraph data={trendData?.data || []} />
          </div>

          {/* Row 3: Charts */}
          <div className="grid md:grid-cols-2 gap-6 mb-8">
            <VulnerabilityChart distribution={vulnDistData?.distribution || {}} />
            <SeverityBarChart distribution={sevDistData?.distribution || {}} />
          </div>
        </>
      ) : (
        <div className="bg-white rounded-2xl shadow-sm p-12 text-center">
          <FolderOpen className="w-12 h-12 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500">Create a project and run a scan to see analytics.</p>
          <Link href="/dashboard/projects"
            className="inline-block mt-3 text-primary-600 font-medium hover:underline">
            Create Project →
          </Link>
        </div>
      )}

      {/* Recent Projects */}
      <div className="bg-white rounded-2xl shadow-sm p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold">Recent Projects</h2>
          <Link href="/dashboard/projects" className="text-primary-600 text-sm font-medium hover:underline">
            View All →
          </Link>
        </div>
        <div className="space-y-2">
          {projects.slice(0, 5).map((p: any) => (
            <Link key={p.id} href={`/dashboard/projects/${p.id}`}
              className="flex items-center justify-between p-3 border rounded-lg hover:bg-gray-50 transition">
              <div>
                <p className="font-medium text-sm">{p.name}</p>
                <p className="text-xs text-gray-400">{p.language} · {p.scan_count} scans</p>
              </div>
              {p.latest_risk_score !== null && (
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold text-white ${
                  p.latest_risk_score >= 8 ? 'bg-red-500' :
                  p.latest_risk_score >= 6 ? 'bg-orange-500' :
                  p.latest_risk_score >= 4 ? 'bg-yellow-500' : 'bg-green-500'
                }`}>{p.latest_risk_score}</span>
              )}
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}