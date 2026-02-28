'use client';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface SeverityBarChartProps {
  distribution: Record<string, number>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#CA8A04',
  low: '#16A34A',
  info: '#6B7280',
};

export default function SeverityBarChart({ distribution }: SeverityBarChartProps) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const data = order
    .filter(sev => (distribution[sev] || 0) > 0)
    .map(sev => ({
      name: sev.charAt(0).toUpperCase() + sev.slice(1),
      count: distribution[sev] || 0,
      severity: sev,
    }));

  if (data.length === 0) {
    return (
      <div className="bg-white rounded-2xl shadow-sm p-6">
        <h3 className="text-sm font-medium text-gray-500 mb-4">Severity Distribution</h3>
        <div className="h-64 flex items-center justify-center text-gray-400">
          No vulnerabilities found
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl shadow-sm p-6">
      <h3 className="text-sm font-medium text-gray-500 mb-4">Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={280}>
        <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
          <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
          <Tooltip formatter={(value: number) => [`${value} vulnerabilities`]} />
          <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={60}>
            {data.map((entry, index) => (
              <Cell key={index} fill={SEVERITY_COLORS[entry.severity]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}