import React from "react";
import { cn } from "@/lib/utils";

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  width?: string | number;
  height?: string | number;
}

export function Skeleton({ className, width, height, ...props }: SkeletonProps) {
  return (
    <div
      className={cn("skeleton rounded-md", className)}
      style={{ width, height }}
      {...props}
    />
  );
}

export function SkeletonLine({ className, ...props }: SkeletonProps) {
  return <Skeleton className={cn("h-4 w-full", className)} {...props} />;
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div className={cn("card p-6 space-y-4", className)}>
      <SkeletonLine className="w-1/3 h-6 mb-4" />
      <SkeletonLine />
      <SkeletonLine className="w-5/6" />
      <SkeletonLine className="w-4/6" />
    </div>
  );
}

export function SkeletonReport() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-24 w-full" />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
      <SkeletonCard className="h-64" />
      <SkeletonCard className="h-48" />
    </div>
  );
}
