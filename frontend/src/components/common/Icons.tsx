import React from "react";

export function MacTrafficLights({ className = "" }: { className?: string }) {
  return (
    <div className={`flex items-center gap-[7px] select-none ${className}`} aria-hidden="true">
      <div className="w-[11px] h-[11px] rounded-full bg-[#FF5F56] border border-[#E0443E]/40" />
      <div className="w-[11px] h-[11px] rounded-full bg-[#FFBD2E] border border-[#DEA123]/40" />
      <div className="w-[11px] h-[11px] rounded-full bg-[#27C93F] border border-[#1AAB29]/40" />
    </div>
  );
}

export function ShieldLogo({ className = "w-5 h-5" }: { className?: string; glow?: boolean }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M12 2L20 5.5V11C20 16.5 16.5 20.8 12 22C7.5 20.8 4 16.5 4 11V5.5L12 2Z"
        fill="currentColor"
        className="text-[#007AFF] dark:text-[#0A84FF]"
        fillOpacity="0.15"
      />
      <path
        d="M12 2L20 5.5V11C20 16.5 16.5 20.8 12 22C7.5 20.8 4 16.5 4 11V5.5L12 2Z"
        stroke="currentColor"
        className="text-[#007AFF] dark:text-[#0A84FF]"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M9 12L11 14L15 10"
        stroke="currentColor"
        className="text-[#007AFF] dark:text-[#0A84FF]"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function GithubIcon({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
      />
    </svg>
  );
}
