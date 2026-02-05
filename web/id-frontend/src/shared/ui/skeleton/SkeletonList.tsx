import React from 'react';
import { SkeletonBlock } from './SkeletonBlock';

export const SkeletonList: React.FC<{ rows?: number }> = ({ rows = 4 }) => (
  <div className="stack" style={{ gap: 10 }}>
    {Array.from({ length: rows }).map((_, i) => (
      <SkeletonBlock key={i} height={44} radius={12} />
    ))}
  </div>
);
