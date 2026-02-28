'use client';
import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import axios from 'axios';
import toast from 'react-hot-toast';

export default function GitHubCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState('Connecting GitHub account...');

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      toast.error('No authorization code received');
      router.push('/dashboard/github');
      return;
    }

    const token = localStorage.getItem('token');
    const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    axios
      .get(`${API_URL}/api/v1/github/callback?code=${code}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then(() => {
        setStatus('Connected!');
        toast.success('GitHub connected successfully!');
        router.push('/dashboard/github');
      })
      .catch((err) => {
        setStatus('Failed to connect');
        toast.error('Failed to connect GitHub');
        router.push('/dashboard/github');
      });
  }, [searchParams, router]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <div className="w-10 h-10 border-4 border-primary-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <p className="text-gray-500">{status}</p>
      </div>
    </div>
  );
}