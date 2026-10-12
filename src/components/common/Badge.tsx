import React from 'react';
import type { RiskSeverity } from '../../types/nmap';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'up' | 'down' | 'open' | 'filtered' | 'closed' | 'critical' | 'high' | 'medium' | 'low' | 'info' | 'format' | 'neutral';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ children, variant = 'neutral', size = 'sm', className = '' }) => {
  const baseStyles = 'inline-flex items-center font-mono font-medium rounded tracking-wide uppercase transition-colors';

  const sizeStyles = {
    sm: 'px-1.5 py-0.5 text-[10px] leading-tight',
    md: 'px-2 py-1 text-xs leading-none',
    lg: 'px-2.5 py-1.5 text-xs font-semibold'
  };

  const variantStyles = {
    up: 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/60',
    down: 'bg-slate-900 text-slate-500 border border-slate-800',
    open: 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80',
    filtered: 'bg-amber-950/70 text-amber-400 border border-amber-800/60',
    closed: 'bg-rose-950/70 text-rose-400 border border-rose-900/60',
    critical: 'bg-red-950 text-red-400 border border-red-800/80 font-bold',
    high: 'bg-orange-950 text-orange-400 border border-orange-800/80 font-semibold',
    medium: 'bg-amber-950 text-amber-400 border border-amber-800/70',
    low: 'bg-blue-950 text-blue-400 border border-blue-800/60',
    info: 'bg-slate-800/80 text-slate-300 border border-slate-700/60',
    format: 'bg-cyan-950/90 text-cyan-300 border border-cyan-800/70 font-semibold',
    neutral: 'bg-slate-800/70 text-slate-300 border border-slate-700/50'
  };

  return (
    <span className={`${baseStyles} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}>
      {children}
    </span>
  );
};

export const RiskSeverityBadge: React.FC<{ severity: RiskSeverity }> = ({ severity }) => {
  return <Badge variant={severity}>{severity}</Badge>;
};
