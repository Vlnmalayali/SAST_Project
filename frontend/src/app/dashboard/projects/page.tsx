'use client';
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProjects, createProject } from '@/lib/api';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { Plus, X } from 'lucide-react';

export default function ProjectsPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', language: 'python', repository_url: '' });

  const { data, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => getProjects().then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: () => createProject(form),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setShowCreate(false);
      setForm({ name: '', description: '', language: 'python', repository_url: '' });
      toast.success('Project created');
    },
    onError: () => toast.error('Failed to create project'),
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-3xl font-bold">Projects</h1>
        <button onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
          <Plus className="w-5 h-5" /> New Project
        </button>
      </div>

      {/* Create Modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl p-8 w-full max-w-lg">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-bold">Create Project</h2>
              <button onClick={() => setShowCreate(false)}><X /></button>
            </div>
            <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(); }} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Project Name</label>
                <input value={form.name} onChange={e => setForm({...form, name: e.target.value})}
                  className="w-full px-4 py-2 border rounded-lg" required />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea value={form.description} onChange={e => setForm({...form, description: e.target.value})}
                  className="w-full px-4 py-2 border rounded-lg" rows={3} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Language</label>
                <select value={form.language} onChange={e => setForm({...form, language: e.target.value})}
                  className="w-full px-4 py-2 border rounded-lg">
                  <option value="python">Python</option>
                  <option value="javascript">JavaScript</option>
                  <option value="java">Java</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Repository URL (optional)</label>
                <input value={form.repository_url} onChange={e => setForm({...form, repository_url: e.target.value})}
                  className="w-full px-4 py-2 border rounded-lg" placeholder="https://github.com/..." />
              </div>
              <button type="submit" disabled={createMutation.isPending}
                className="w-full py-3 bg-primary-600 text-white rounded-lg font-semibold hover:bg-primary-700 disabled:opacity-50">
                {createMutation.isPending ? 'Creating...' : 'Create Project'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Project Grid */}
      {isLoading ? (
        <div className="text-center py-20 text-gray-400">Loading...</div>
      ) : (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {(data?.projects || []).map((p: any) => (
            <Link key={p.id} href={`/dashboard/projects/${p.id}`}
              className="bg-white rounded-xl shadow-sm p-6 hover:shadow-md transition">
              <h3 className="text-lg font-bold mb-1">{p.name}</h3>
              <p className="text-sm text-gray-500 mb-4">{p.description || 'No description'}</p>
              <div className="flex items-center justify-between text-sm">
                <span className="bg-blue-100 text-blue-700 px-2 py-1 rounded">{p.language}</span>
                <span className="text-gray-500">{p.scan_count} scans</span>
                {p.latest_risk_score !== null && (
                  <span className={`font-bold ${
                    p.latest_risk_score >= 7 ? 'text-red-600' :
                    p.latest_risk_score >= 4 ? 'text-yellow-600' : 'text-green-600'
                  }`}>
                    Risk: {p.latest_risk_score}
                  </span>
                )}
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}