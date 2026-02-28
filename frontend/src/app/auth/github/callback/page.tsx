'use client';
import { Suspense } from 'react';
import GitHubCallbackContent from './CallbackContent';

export default function GitHubCallbackPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-10 h-10 border-4 border-primary-600 border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <GitHubCallbackContent />
    </Suspense>
  );
}