'use client';
import { useQuery } from '@tanstack/react-query';
import { getProjects, getProjectScans } from '@/lib/api';
import Link from 'next/link';
import { Clock, AlertTriangle } from 'lucide-react';

export default function ScansPage() {
  const { data: projectsData } = useQuery({
    queryKey: ['projects'],
    queryFn: () => getProjects().then(r => r.data),
  });

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">All Scans</h1>
      <p className="text-gray-500 mb-6">Select a project to view its scans, or navigate from the project detail page.</p>

      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        {(projectsData?.projects || []).map((p: any) => (
          <Link key={p.id} href={`/dashboard/projects/${p.id}`}
            className="bg-white rounded-xl shadow-sm p-5 hover:shadow-md transition">
            <h3 className="font-bold mb-1">{p.name}</h3>
            <p className="text-sm text-gray-500">{p.scan_count} scans · {p.language}</p>
            {p.latest_risk_score !== null && (
              <div className="mt-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-500" />
                <span className="text-sm font-medium">Risk: {p.latest_risk_score}/10</span>
              </div>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
}