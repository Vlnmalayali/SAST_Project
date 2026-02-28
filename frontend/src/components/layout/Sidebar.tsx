'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { cn } from '@/lib/utils';
import { Shield, LayoutDashboard, FolderOpen, ScanLine, FileText, Github, LogOut } from 'lucide-react';

const links = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/dashboard/projects', label: 'Projects', icon: FolderOpen },
  { href: '/dashboard/scans', label: 'Scans', icon: ScanLine },
  { href: '/dashboard/github', label: 'GitHub', icon: Github },
  { href: '/dashboard/reports', label: 'Reports', icon: FileText },
];


export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <aside className="w-64 bg-primary-900 text-white min-h-screen p-6 flex flex-col">
      <div className="flex items-center gap-2 mb-10">
        <Shield className="w-7 h-7" />
        <span className="text-xl font-bold">AI-SAST</span>
      </div>

      <nav className="flex-1 space-y-2">
        {links.map(({ href, label, icon: Icon }) => (
          <Link key={href} href={href}
            className={cn(
              'flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition',
              pathname === href ? 'bg-white/20 text-white' : 'text-blue-200 hover:bg-white/10'
            )}>
            <Icon className="w-5 h-5" />
            {label}
          </Link>
        ))}
      </nav>

      <button onClick={() => { localStorage.clear(); router.push('/login'); }}
        className="flex items-center gap-3 px-4 py-2.5 text-blue-200 hover:bg-white/10 rounded-lg text-sm">
        <LogOut className="w-5 h-5" /> Sign Out
      </button>
    </aside>
  );
}