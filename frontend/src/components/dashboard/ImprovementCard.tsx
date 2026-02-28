'use client';
import { TrendingDown, TrendingUp, Minus } from 'lucide-react';

interface ImprovementCardProps {
  summary: {
    total_scans: number;
    completed_scans: number;
    latest_risk_score: number | null;
    latest_vulnerability_count: number;
    risk_improvement_percentage: number | null;
  } | null;
}

export default function ImprovementCard({ summary }: ImprovementCardProps) {
  if (!summary) return null;

  const improvement = summary.risk_improvement_percentage;

  return (
    <div className="bg-white rounded-2xl shadow-sm p-6">
      <h3 className="text-sm font-medium text-gray-500 mb-4">Security Improvement</h3>

      <div className="grid grid-cols-2 gap-4">
        <div className="text-center p-4 bg-gray-50 rounded-xl">
          <p className="text-2xl font-bold text-primary-600">{summary.completed_scans}</p>
          <p className="text-xs text-gray-500">Scans Completed</p>
        </div>
        <div className="text-center p-4 bg-gray-50 rounded-xl">
          <p className="text-2xl font-bold">{summary.latest_vulnerability_count}</p>
          <p className="text-xs text-gray-500">Active Issues</p>
        </div>
      </div>

      {improvement !== null && (
        <div className={`mt-4 p-4 rounded-xl flex items-center gap-3 ${
          improvement > 0 ? 'bg-green-50' : improvement < 0 ? 'bg-red-50' : 'bg-gray-50'
        }`}>
          {improvement > 0 ? (
            <TrendingDown className="w-8 h-8 text-green-500" />
          ) : improvement < 0 ? (
            <TrendingUp className="w-8 h-8 text-red-500" />
          ) : (
            <Minus className="w-8 h-8 text-gray-400" />
          )}
          <div>
            <p className={`text-lg font-bold ${
              improvement > 0 ? 'text-green-700' : improvement < 0 ? 'text-red-700' : 'text-gray-600'
            }`}>
              {improvement > 0 ? '+' : ''}{improvement}% {improvement > 0 ? 'Improvement' : improvement < 0 ? 'Regression' : 'No Change'}
            </p>
            <p className="text-xs text-gray-500">Compared to first scan</p>
          </div>
        </div>
      )}
    </div>
  );
}