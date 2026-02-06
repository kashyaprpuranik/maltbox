import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  KeyRound,
  Key,
  Shield,
  Gauge,
  FileText,
  ScrollText,
  Settings,
  Building2,
  LogOut,
  ExternalLink,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../api/client';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/secrets', icon: KeyRound, label: 'Secrets' },
  { to: '/allowlist', icon: Shield, label: 'Allowlist' },
  { to: '/rate-limits', icon: Gauge, label: 'Rate Limits' },
  { to: '/tokens', icon: Key, label: 'API Tokens' },
  { to: '/tenants', icon: Building2, label: 'Tenants', superAdminOnly: true },
  { to: '/admin-logs', icon: FileText, label: 'Admin Logs' },
  { to: '/agent-logs', icon: ScrollText, label: 'Agent Logs' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export function Sidebar() {
  const { user, refresh } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    api.clearToken();
    refresh();
    navigate('/login');
  };

  return (
    <aside className="w-64 bg-dark-900 border-r border-dark-700 flex flex-col">
      <div className="p-4 border-b border-dark-700">
        <h1 className="text-xl font-bold text-dark-100">Maltbox</h1>
        <p className="text-sm text-dark-500">Admin Console</p>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        {navItems
          .filter(item => !item.superAdminOnly || user?.is_super_admin)
          .map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                isActive
                  ? 'bg-dark-700 text-dark-100'
                  : 'text-dark-400 hover:bg-dark-800 hover:text-dark-200'
              }`
            }
          >
            <Icon size={20} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="p-4 border-t border-dark-700 space-y-2">
        {user?.is_super_admin && (
          <a
            href="/openobserve/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-sm text-dark-500 hover:text-dark-300"
          >
            <ExternalLink size={16} />
            OpenObserve
          </a>
        )}
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 text-sm text-dark-500 hover:text-dark-300 w-full"
        >
          <LogOut size={16} />
          Logout
        </button>
      </div>
    </aside>
  );
}
