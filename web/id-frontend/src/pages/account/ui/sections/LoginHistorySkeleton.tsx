import React from 'react';
import { SkeletonText } from '../../../../shared/ui/skeleton/SkeletonText';
import { SkeletonList } from '../../../../shared/ui/skeleton/SkeletonList';

export const LoginHistorySkeleton = () => (
  <div className="card">
    <SkeletonText width={140} height={18} />
    <div style={{ height: 12 }} />
    <SkeletonList rows={4} />
  </div>
);
