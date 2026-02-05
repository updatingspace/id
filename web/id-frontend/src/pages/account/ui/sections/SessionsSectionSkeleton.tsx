import React from 'react';
import { SkeletonText } from '../../../../shared/ui/skeleton/SkeletonText';
import { SkeletonList } from '../../../../shared/ui/skeleton/SkeletonList';
import { SkeletonBlock } from '../../../../shared/ui/skeleton/SkeletonBlock';

export const SessionsSectionSkeleton = () => (
  <div className="card">
    <SkeletonText width={140} height={18} />
    <div style={{ height: 12 }} />
    <SkeletonList rows={4} />
    <div style={{ height: 14 }} />
    <SkeletonBlock width={220} height={40} radius={12} />
  </div>
);
