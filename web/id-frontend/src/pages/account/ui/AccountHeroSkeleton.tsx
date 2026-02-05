import React from 'react';
import { SkeletonBlock } from '../../../shared/ui/skeleton/SkeletonBlock';
import { SkeletonText } from '../../../shared/ui/skeleton/SkeletonText';

export const AccountHeroSkeleton = () => (
  <div className="account-hero">
    <div className="account-hero-main">
      <SkeletonBlock width={54} height={54} radius={999} />
      <div className="hero-meta" style={{ width: '100%' }}>
        <SkeletonText width={120} />
        <div style={{ height: 8 }} />
        <SkeletonText width="60%" height={22} />
        <div style={{ height: 8 }} />
        <SkeletonText width="45%" />
        <div style={{ height: 10 }} />
        <div className="hero-badges" style={{ display: 'flex', gap: 8 }}>
          <SkeletonBlock width={90} height={22} radius={999} />
          <SkeletonBlock width={110} height={22} radius={999} />
          <SkeletonBlock width={80} height={22} radius={999} />
        </div>
      </div>
    </div>

    <div className="hero-actions">
      <div className="hero-stat">
        <SkeletonText width={40} />
        <SkeletonText width={80} height={18} />
      </div>
      <div className="hero-stat">
        <SkeletonText width={70} />
        <SkeletonText width={40} height={18} />
      </div>
      <div className="hero-stat">
        <SkeletonText width={70} />
        <SkeletonText width={40} height={18} />
      </div>
    </div>
  </div>
);
