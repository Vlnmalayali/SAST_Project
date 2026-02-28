'use client';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Area, AreaChart } from 'recharts';

interface TrendGraphProps {
  data: Array<{ date: string; risk_score: number }>;
}

export default function TrendGraph({ data }: TrendGraphProps) {
  const formatted = data.map(d => ({
    ...d,
    date: new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
  }));

  if (formatted.length < 2) {
    return (
      <div className="bg-white rounded-2xl shadow-sm p-6">
        <h3 className="text-sm font-medium text-gray-500 mb-4">Risk Score Trend</h3>
        <div className="h-64 flex items-center justify-center text-gray-400">
          Need at least 2 scans to show trends
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl shadow-sm p-6">
      <h3 className="text-sm font-medium text-gray-500 mb-4">Risk Score Trend</h3>
      <ResponsiveContainer width="100%" height={280}>
        <AreaChart data={formatted} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
          <defs>
            <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6" />
          <XAxis dataKey="date" tick={{ fontSize: 11 }} />
          <YAxis domain={[0, 10]} tick={{ fontSize: 11 }} />
          <Tooltip
            formatter={(value: number) => [`${value}/10`, 'Risk Score']}
            labelStyle={{ fontWeight: 'bold' }}
          />
          <Area
            type="monotone"
            dataKey="risk_score"
            stroke="#3B82F6"
            strokeWidth={2.5}
            fill="url(#riskGradient)"
            dot={{ r: 4, fill: '#3B82F6' }}
            activeDot={{ r: 6 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}