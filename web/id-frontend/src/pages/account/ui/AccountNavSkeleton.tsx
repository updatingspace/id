import React from 'react';
import { SkeletonText } from '../../../shared/ui/skeleton/SkeletonText';
import { SkeletonBlock } from '../../../shared/ui/skeleton/SkeletonBlock';

export const AccountNavSkeleton = () => (
  <aside className="account-nav">
    <SkeletonText width={140} height={18} />
    <div style={{ height: 12 }} />
    <div className="stack" style={{ gap: 10 }}>
      {Array.from({ length: 6 }).map((_, i) => (
        <SkeletonBlock key={i} height={34} radius={999} />
      ))}
    </div>
    <div style={{ height: 18 }} />
    <SkeletonBlock height={54} radius={14} />
  </aside>
);
