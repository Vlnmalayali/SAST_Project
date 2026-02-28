'use client';

interface RiskScoreCardProps {
  score: number | null;
  previousScore?: number | null;
}

export default function RiskScoreCard({ score, previousScore }: RiskScoreCardProps) {
  const displayScore = score ?? 0;

  const getColor = (s: number) => {
    if (s >= 8) return { bg: 'bg-red-500', text: 'text-red-600', ring: 'ring-red-200', label: 'Critical' };
    if (s >= 6) return { bg: 'bg-orange-500', text: 'text-orange-600', ring: 'ring-orange-200', label: 'High' };
    if (s >= 4) return { bg: 'bg-yellow-500', text: 'text-yellow-600', ring: 'ring-yellow-200', label: 'Medium' };
    if (s >= 2) return { bg: 'bg-green-500', text: 'text-green-600', ring: 'ring-green-200', label: 'Low' };
    return { bg: 'bg-emerald-500', text: 'text-emerald-600', ring: 'ring-emerald-200', label: 'Minimal' };
  };

  const color = getColor(displayScore);
  const percentage = (displayScore / 10) * 100;
  const circumference = 2 * Math.PI * 60;
  const offset = circumference - (percentage / 100) * circumference;

  let trend: 'up' | 'down' | 'same' = 'same';
  if (previousScore !== null && previousScore !== undefined && score !== null) {
    if (score < previousScore) trend = 'down';
    else if (score > previousScore) trend = 'up';
  }

  return (
    <div className="bg-white rounded-2xl shadow-sm p-6 flex items-center gap-6">
      {/* Circular gauge */}
      <div className="relative w-36 h-36 flex-shrink-0">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="60" fill="none" stroke="#E5E7EB" strokeWidth="12" />
          <circle cx="70" cy="70" r="60" fill="none"
            stroke={displayScore >= 8 ? '#DC2626' : displayScore >= 6 ? '#EA580C' : displayScore >= 4 ? '#CA8A04' : '#16A34A'}
            strokeWidth="12" strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold ${color.text}`}>{displayScore}</span>
          <span className="text-xs text-gray-400">/ 10.0</span>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-medium text-gray-500 mb-1">Risk Score</h3>
        <p className={`text-lg font-bold ${color.text}`}>{color.label} Risk</p>
        {trend !== 'same' && (
          <p className={`text-sm mt-1 ${trend === 'down' ? 'text-green-600' : 'text-red-600'}`}>
            {trend === 'down' ? '↓ Improved' : '↑ Increased'} from {previousScore}
          </p>
        )}
      </div>
    </div>
  );
}