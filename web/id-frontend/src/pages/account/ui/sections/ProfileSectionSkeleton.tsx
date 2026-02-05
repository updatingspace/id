import React from 'react';
import { SkeletonText } from '../../../../shared/ui/skeleton/SkeletonText';
import { SkeletonBlock } from '../../../../shared/ui/skeleton/SkeletonBlock';

export const ProfileSectionSkeleton = () => (
  <div className="stack">
    <div className="card">
      <SkeletonText width={160} height={18} />
      <div style={{ height: 14 }} />
      <div className="form-grid">
        <SkeletonBlock height={44} />
        <SkeletonBlock height={44} />
        <SkeletonBlock height={44} />
        <SkeletonBlock height={44} />
      </div>
      <div style={{ height: 14 }} />
      <SkeletonBlock width={180} height={40} radius={12} />
    </div>

    <div className="card">
      <SkeletonText width={190} height={18} />
      <div style={{ height: 14 }} />
      <SkeletonBlock height={52} />
      <div style={{ height: 12 }} />
      <SkeletonBlock height={44} />
    </div>
  </div>
);
