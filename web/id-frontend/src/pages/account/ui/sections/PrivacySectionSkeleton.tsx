import React from 'react';
import { SkeletonText } from '../../../../shared/ui/skeleton/SkeletonText';
import { SkeletonBlock } from '../../../../shared/ui/skeleton/SkeletonBlock';
import { SkeletonList } from '../../../../shared/ui/skeleton/SkeletonList';

export const PrivacySectionSkeleton = () => (
  <div className="stack">
    <div className="card">
      <SkeletonText width={160} height={18} />
      <div style={{ height: 14 }} />
      <div className="form-grid">
        <SkeletonBlock height={44} />
        <SkeletonBlock height={44} />
        <SkeletonBlock height={24} radius={8} />
      </div>
      <div style={{ height: 14 }} />
      <div className="scope-grid">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="scope-policy">
            <SkeletonText width={110} />
            <div className="pill-row" style={{ gap: 8 }}>
              <SkeletonBlock width={60} height={28} radius={999} />
              <SkeletonBlock width={60} height={28} radius={999} />
              <SkeletonBlock width={60} height={28} radius={999} />
            </div>
          </div>
        ))}
      </div>
      <div style={{ height: 14 }} />
      <SkeletonBlock width={200} height={40} radius={12} />
    </div>

    <div className="card">
      <SkeletonText width={120} height={18} />
      <div style={{ height: 12 }} />
      <SkeletonList rows={3} />
    </div>
  </div>
);
