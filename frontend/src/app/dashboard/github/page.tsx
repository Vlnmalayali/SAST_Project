'use client';
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getGithubOAuth, getGithubRepos, triggerGithubScan, getProjects } from '@/lib/api';
import toast from 'react-hot-toast';
import { Github, GitBranch, Lock, Unlock, Loader2, Search, Play } from 'lucide-react';

export default function GitHubPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [selectedRepo, setSelectedRepo] = useState<any>(null);
  const [branch, setBranch] = useState('main');
  const [selectedProject, setSelectedProject] = useState('');

  const { data: reposData, isLoading: reposLoading, error: reposError } = useQuery({
    queryKey: ['github-repos'],
    queryFn: () => getGithubRepos().then(r => r.data),
    retry: false,
  });

  const { data: projectsData } = useQuery({
    queryKey: ['projects'],
    queryFn: () => getProjects().then(r => r.data),
  });

  const isConnected = !reposError;
  const repos = reposData?.repos || [];
  const projects = projectsData?.projects || [];

  const filteredRepos = repos.filter((r: any) =>
    r.full_name.toLowerCase().includes(search.toLowerCase())
  );

  const connectGithub = async () => {
    try {
      const { data } = await getGithubOAuth();
      window.location.href = data.auth_url;
    } catch {
      toast.error('Failed to start GitHub OAuth');
    }
  };

  const scanMutation = useMutation({
    mutationFn: () => triggerGithubScan({
      repo_full_name: selectedRepo.full_name,
      branch,
      project_id: selectedProject,
    }),
    onSuccess: (data) => {
      toast.success(`Scan started! ID: ${data.data.scan_id.slice(0, 8)}`);
      setSelectedRepo(null);
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to start scan');
    },
  });

  return (
    <div>
      <div className="flex items-center gap-3 mb-8">
        <Github className="w-8 h-8" />
        <h1 className="text-3xl font-bold">GitHub Integration</h1>
      </div>

      {!isConnected ? (
        /* Not Connected */
        <div className="bg-white rounded-2xl shadow-sm p-12 text-center max-w-lg mx-auto">
          <Github className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h2 className="text-xl font-bold mb-2">Connect Your GitHub Account</h2>
          <p className="text-gray-500 mb-6">
            Link your GitHub account to scan repositories directly and get
            automated security checks on pull requests.
          </p>
          <button onClick={connectGithub}
            className="inline-flex items-center gap-2 px-6 py-3 bg-gray-900 text-white rounded-xl font-medium hover:bg-gray-800 transition">
            <Github className="w-5 h-5" />
            Connect GitHub
          </button>
        </div>
      ) : (
        /* Connected — Show Repos */
        <div className="space-y-6">
          {/* Search */}
          <div className="relative">
            <Search className="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search repositories..."
              className="w-full pl-10 pr-4 py-3 border rounded-xl focus:ring-2 focus:ring-primary-500 outline-none"
            />
          </div>

          {/* Scan Config Modal */}
          {selectedRepo && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
              <div className="bg-white rounded-2xl p-8 w-full max-w-md">
                <h3 className="text-lg font-bold mb-4">Scan Repository</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Repository</label>
                    <p className="text-gray-700 font-mono text-sm bg-gray-50 px-3 py-2 rounded-lg">
                      {selectedRepo.full_name}
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Branch</label>
                    <input value={branch} onChange={(e) => setBranch(e.target.value)}
                      className="w-full px-4 py-2 border rounded-lg" placeholder="main" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Target Project</label>
                    <select value={selectedProject}
                      onChange={(e) => setSelectedProject(e.target.value)}
                      className="w-full px-4 py-2 border rounded-lg">
                      <option value="">Select a project...</option>
                      {projects.map((p: any) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                    </select>
                  </div>
                  <div className="flex gap-3 pt-2">
                    <button onClick={() => setSelectedRepo(null)}
                      className="flex-1 py-2 border rounded-lg hover:bg-gray-50">
                      Cancel
                    </button>
                    <button
                      onClick={() => scanMutation.mutate()}
                      disabled={!selectedProject || scanMutation.isPending}
                      className="flex-1 py-2 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 disabled:opacity-50">
                      {scanMutation.isPending ? (
                        <><Loader2 className="w-4 h-4 animate-spin inline mr-1" /> Scanning...</>
                      ) : (
                        <><Play className="w-4 h-4 inline mr-1" /> Start Scan</>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Repo List */}
          {reposLoading ? (
            <div className="text-center py-12">
              <Loader2 className="w-8 h-8 animate-spin mx-auto text-gray-400" />
            </div>
          ) : (
            <div className="grid gap-3">
              {filteredRepos.map((repo: any) => (
                <div key={repo.id}
                  className="bg-white rounded-xl shadow-sm p-5 flex items-center justify-between hover:shadow-md transition">
                  <div className="flex items-center gap-3 min-w-0">
                    {repo.private
                      ? <Lock className="w-4 h-4 text-yellow-500 flex-shrink-0" />
                      : <Unlock className="w-4 h-4 text-green-500 flex-shrink-0" />
                    }
                    <div className="min-w-0">
                      <p className="font-medium truncate">{repo.full_name}</p>
                      <div className="flex items-center gap-2 text-xs text-gray-400">
                        {repo.language && (
                          <span className="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
                            {repo.language}
                          </span>
                        )}
                        <span>{repo.private ? 'Private' : 'Public'}</span>
                      </div>
                    </div>
                  </div>
                  <button onClick={() => { setSelectedRepo(repo); setBranch('main'); }}
                    className="px-4 py-1.5 bg-primary-600 text-white rounded-lg text-sm font-medium hover:bg-primary-700 flex-shrink-0">
                    Scan
                  </button>
                </div>
              ))}
              {filteredRepos.length === 0 && (
                <p className="text-center text-gray-400 py-8">No repositories found</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}