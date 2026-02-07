import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Key,
  FileText,
  ScrollText,
  Settings,
  Building2,
  LogOut,
  ExternalLink,
  Network,
  Globe,
  LucideIcon,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../api/client';

interface NavItem {
  to: string;
  icon: LucideIcon;
  label: string;
  superAdminOnly?: boolean;
  adminOnly?: boolean;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: 'Observability',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/admin-logs', icon: FileText, label: 'Admin Logs', adminOnly: true },
      { to: '/agent-logs', icon: ScrollText, label: 'Agent Logs' },
    ],
  },
  {
    title: 'Configuration',
    items: [
      { to: '/domain-policies', icon: Globe, label: 'Domain Policies', adminOnly: true },
      { to: '/ip-acls', icon: Network, label: 'IP ACLs', adminOnly: true },
    ],
  },
  {
    title: 'Administration',
    items: [
      { to: '/tokens', icon: Key, label: 'API Tokens', adminOnly: true },
      { to: '/tenants', icon: Building2, label: 'Tenants', superAdminOnly: true },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export function Sidebar() {
  const { user, refresh } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    api.clearToken();
    await refresh();
    navigate('/login');
  };

  // Check if user has admin role
  const hasAdminRole = user?.is_super_admin || user?.roles?.includes('admin');

  // Filter nav items based on user roles
  const filterItems = (items: NavItem[]) =>
    items.filter((item) => {
      if (item.superAdminOnly && !user?.is_super_admin) return false;
      if (item.adminOnly && !hasAdminRole) return false;
      return true;
    });

  return (
    <aside className="w-64 bg-dark-900 border-r border-dark-700 flex flex-col">
      <div className="p-4 border-b border-dark-700">
        <h1 className="text-xl font-bold text-dark-100">Cagent</h1>
        <p className="text-sm text-dark-500">
          {user?.is_super_admin ? 'Super Admin' : hasAdminRole ? 'Admin' : 'Developer'}
        </p>
      </div>
      <nav className="flex-1 p-4 space-y-6 overflow-y-auto">
        {navSections.map((section) => {
          const filteredItems = filterItems(section.items);
          if (filteredItems.length === 0) return null;

          return (
            <div key={section.title}>
              <h2 className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-2 px-3">
                {section.title}
              </h2>
              <div className="space-y-1">
                {filteredItems.map(({ to, icon: Icon, label }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === '/'}
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
              </div>
            </div>
          );
        })}
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
