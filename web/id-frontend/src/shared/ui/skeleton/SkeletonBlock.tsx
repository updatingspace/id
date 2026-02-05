import React from 'react';
import { Skeleton } from '@gravity-ui/uikit';

export const SkeletonBlock: React.FC<{ width?: number | string; height?: number; radius?: number }> = ({
  width = '100%',
  height = 36,
  radius = 12,
}) => <Skeleton style={{ width, height, borderRadius: radius }} />;
