import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: React.ReactNode;
  children: React.ReactNode;
  width?: 'md' | 'lg' | 'xl' | '2xl' | 'full';
  drawer?: boolean;
}

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  width = 'xl',
  drawer = false
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.body.style.overflow = 'hidden';
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.body.style.overflow = 'unset';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const widthClasses = {
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-3xl',
    '2xl': 'max-w-5xl',
    full: 'max-w-7xl'
  };

  if (drawer) {
    return (
      <div className="fixed inset-0 z-50 overflow-hidden bg-black/70 backdrop-blur-xs flex justify-end">
        <div
          className="w-full max-w-3xl bg-[#13161f] border-l border-[#202636] h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-6 py-4 bg-[#0f121a] border-b border-[#202636] flex items-center justify-between">
            <div className="text-base font-semibold text-slate-100">{title}</div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-[#1f2638] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="flex-1 overflow-y-auto p-6">{children}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
      <div
        className={`w-full ${widthClasses[width]} bg-[#13161f] border border-[#202636] rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 py-4 bg-[#0f121a] border-b border-[#202636] flex items-center justify-between">
          <div className="text-base font-semibold text-slate-100">{title}</div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-[#1f2638] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-6">{children}</div>
      </div>
    </div>
  );
};
