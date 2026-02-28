'use client';
import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { getSandboxStatus, runSandboxTest } from '@/lib/api';
import { FlaskConical, CheckCircle, XCircle, AlertTriangle, Loader2 } from 'lucide-react';
import toast from 'react-hot-toast';

interface SandboxTestPanelProps {
  scanId: string;
}

export default function SandboxTestPanel({ scanId }: SandboxTestPanelProps) {
  const [results, setResults] = useState<any>(null);

  const { data: status } = useQuery({
    queryKey: ['sandbox-status'],
    queryFn: () => getSandboxStatus().then(r => r.data),
  });

  const testMutation = useMutation({
    mutationFn: () => runSandboxTest(scanId),
    onSuccess: (data) => {
      setResults(data.data);
      toast.success(`Tested ${data.data.total_tested} vulnerabilities`);
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Sandbox test failed');
    },
  });

  if (!status?.available) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-sm text-yellow-700">
        <FlaskConical className="w-4 h-4 inline mr-1" />
        Docker sandbox is not available. Enable it in .env with ENABLE_SANDBOX=true.
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl shadow-sm p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <FlaskConical className="w-5 h-5 text-purple-600" />
          <h3 className="text-lg font-bold">Exploit Simulation</h3>
        </div>
        <button
          onClick={() => testMutation.mutate()}
          disabled={testMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg text-sm font-medium hover:bg-purple-700 disabled:opacity-50">
          {testMutation.isPending ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Testing...</>
          ) : (
            <><FlaskConical className="w-4 h-4" /> Run Exploit Tests</>
          )}
        </button>
      </div>

      <p className="text-sm text-gray-500 mb-4">
        Tests critical and high severity vulnerabilities in an isolated Docker container to confirm exploitability.
      </p>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="grid grid-cols-4 gap-3 text-center">
            <div className="p-3 bg-gray-50 rounded-lg">
              <p className="text-xl font-bold">{results.total_tested}</p>
              <p className="text-xs text-gray-500">Tested</p>
            </div>
            <div className="p-3 bg-red-50 rounded-lg">
              <p className="text-xl font-bold text-red-600">{results.confirmed_exploitable}</p>
              <p className="text-xs text-red-500">Confirmed</p>
            </div>
            <div className="p-3 bg-green-50 rounded-lg">
              <p className="text-xl font-bold text-green-600">{results.not_confirmed}</p>
              <p className="text-xs text-green-500">Not Confirmed</p>
            </div>
            <div className="p-3 bg-yellow-50 rounded-lg">
              <p className="text-xl font-bold text-yellow-600">{results.errors}</p>
              <p className="text-xs text-yellow-500">Errors</p>
            </div>
          </div>

          {/* Individual Results */}
          <div className="space-y-2">
            {results.results.map((r: any, i: number) => (
              <div key={i} className={`p-3 rounded-lg border flex items-center justify-between ${
                r.exploitable ? 'bg-red-50 border-red-200' :
                r.status === 'error' ? 'bg-yellow-50 border-yellow-200' :
                'bg-green-50 border-green-200'
              }`}>
                <div className="flex items-center gap-2">
                  {r.exploitable ? (
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                  ) : r.status === 'error' ? (
                    <XCircle className="w-4 h-4 text-yellow-500" />
                  ) : (
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  )}
                  <span className="text-sm font-medium">
                    {r.vulnerability_type.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs">
                  <span className={`px-2 py-0.5 rounded-full font-medium ${
                    r.exploitable ? 'bg-red-100 text-red-700' :
                    r.status === 'error' ? 'bg-yellow-100 text-yellow-700' :
                    'bg-green-100 text-green-700'
                  }`}>
                    {r.exploitable ? 'EXPLOITABLE' : r.status === 'error' ? 'ERROR' : 'SAFE'}
                  </span>
                  <span className="text-gray-400">{r.time}s</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}