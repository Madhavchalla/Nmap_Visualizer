import React from 'react';

interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  headerAction?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  icon,
  headerAction,
  children,
  className = '',
  bodyClassName = 'p-4'
}) => {
  return (
    <div className={`bg-[#13161f] border border-[#202636] rounded-lg overflow-hidden shadow-lg ${className}`}>
      {(title || headerAction) && (
        <div className="px-4 py-3 bg-[#0f121a] border-b border-[#202636] flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            {icon && <span className="text-cyan-400">{icon}</span>}
            <div>
              {typeof title === 'string' ? (
                <h3 className="text-sm font-semibold text-slate-200 tracking-wide font-sans">{title}</h3>
              ) : (
                title
              )}
              {subtitle && <p className="text-xs text-slate-400 font-sans mt-0.5">{subtitle}</p>}
            </div>
          </div>
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </div>
  );
};
