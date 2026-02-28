'use client';
import Link from 'next/link';
import { Shield, Zap, FileText, Github } from 'lucide-react';

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-900 to-blue-800 text-white">
      <nav className="flex items-center justify-between px-8 py-4">
        <div className="text-2xl font-bold flex items-center gap-2">
          <Shield className="w-8 h-8" /> AI-SAST
        </div>
        <div className="flex gap-4">
          <Link href="/login" className="px-4 py-2 rounded-lg border border-white/30 hover:bg-white/10">
            Login
          </Link>
          <Link href="/register" className="px-4 py-2 bg-white text-primary-900 rounded-lg font-semibold hover:bg-gray-100">
            Get Started
          </Link>
        </div>
      </nav>

      <main className="max-w-5xl mx-auto px-8 py-20 text-center">
        <h1 className="text-5xl font-bold mb-6">AI-Powered Security Analysis</h1>
        <p className="text-xl text-blue-200 mb-12 max-w-2xl mx-auto">
          Detect vulnerabilities in your code using AST analysis and GPT-4 powered explanations.
          Get actionable fixes and professional security reports.
        </p>

        <Link href="/register" className="inline-block px-8 py-4 bg-white text-primary-900 rounded-xl text-lg font-bold hover:bg-gray-100 transition">
          Start Scanning Free →
        </Link>

        <div className="grid md:grid-cols-4 gap-8 mt-20 text-left">
          {[
            { icon: Shield, title: '8+ Detectors', desc: 'SQL injection, XSS, secrets, and more' },
            { icon: Zap, title: 'AI Explanations', desc: 'GPT-4 powered vulnerability analysis' },
            { icon: FileText, title: 'PDF Reports', desc: 'Professional security audit reports' },
            { icon: Github, title: 'GitHub Integration', desc: 'Scan repos and comment on PRs' },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="bg-white/10 backdrop-blur rounded-xl p-6">
              <Icon className="w-10 h-10 mb-3 text-blue-300" />
              <h3 className="font-bold text-lg mb-1">{title}</h3>
              <p className="text-blue-200 text-sm">{desc}</p>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}