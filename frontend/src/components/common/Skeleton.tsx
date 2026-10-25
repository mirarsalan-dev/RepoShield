import React from "react";

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className = "" }: SkeletonProps) {
  return (
    <div
      className={`animate-pulse bg-[var(--surface-secondary)] rounded-[var(--radius-sm)] ${className}`}
      aria-hidden="true"
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="macos-panel p-4 space-y-3">
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-8 w-1/2" />
      <Skeleton className="h-3 w-2/3" />
    </div>
  );
}

export function SkeletonTableRow() {
  return (
    <div className="flex items-center gap-4 py-3 px-3 border-b border-[var(--border)]">
      <Skeleton className="h-4 w-16" />
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-4 w-1/4" />
      <Skeleton className="h-4 w-12 ml-auto" />
    </div>
  );
}
