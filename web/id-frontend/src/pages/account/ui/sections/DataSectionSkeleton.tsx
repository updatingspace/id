import React from 'react';
import { SkeletonText } from '../../../../shared/ui/skeleton/SkeletonText';
import { SkeletonBlock } from '../../../../shared/ui/skeleton/SkeletonBlock';

export const DataSectionSkeleton = () => (
  <div className="stack">
    <div className="card">
      <SkeletonText width={140} height={18} />
      <div style={{ height: 10 }} />
      <SkeletonText width="80%" />
      <div style={{ height: 12 }} />
      <div className="form-row" style={{ gap: 12 }}>
        <SkeletonBlock height={44} />
        <SkeletonBlock height={44} />
      </div>
      <div style={{ height: 12 }} />
      <SkeletonBlock width={220} height={40} radius={12} />
    </div>

    <div className="card danger">
      <SkeletonText width={180} height={18} />
      <div style={{ height: 10 }} />
      <SkeletonText width="90%" />
      <div style={{ height: 12 }} />
      <SkeletonBlock width={260} height={40} radius={12} />
    </div>
  </div>
);
