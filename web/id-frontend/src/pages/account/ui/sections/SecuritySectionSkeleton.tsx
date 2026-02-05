import React from 'react';
import { SkeletonText } from '../../../../shared/ui/skeleton/SkeletonText';
import { SkeletonBlock } from '../../../../shared/ui/skeleton/SkeletonBlock';
import { SkeletonList } from '../../../../shared/ui/skeleton/SkeletonList';

export const SecuritySectionSkeleton = () => (
  <div className="stack">
    <div className="card">
      <SkeletonText width={190} height={18} />
      <div style={{ height: 14 }} />
      <div className="form-grid">
        <SkeletonBlock height={44} />
        <SkeletonBlock height={44} />
      </div>
      <div style={{ height: 14 }} />
      <SkeletonBlock width={220} height={40} radius={12} />
    </div>

    <div className="card">
      <SkeletonText width={150} height={18} />
      <div style={{ height: 10 }} />
      <SkeletonText width={120} />
      <div style={{ height: 12 }} />
      <div className="row" style={{ gap: 10 }}>
        <SkeletonBlock width={180} height={40} radius={12} />
        <SkeletonBlock width={210} height={40} radius={12} />
      </div>
      <div style={{ height: 12 }} />
      <SkeletonBlock height={140} radius={14} />
    </div>

    <div className="card">
      <SkeletonText width={160} height={18} />
      <div style={{ height: 12 }} />
      <SkeletonList rows={3} />
      <div style={{ height: 12 }} />
      <SkeletonBlock width={200} height={40} radius={12} />
    </div>

    <div className="card">
      <SkeletonText width={170} height={18} />
      <div style={{ height: 12 }} />
      <SkeletonList rows={3} />
    </div>
  </div>
);
