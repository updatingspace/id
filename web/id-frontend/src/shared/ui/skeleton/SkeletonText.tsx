import React from 'react';
import { Skeleton } from '@gravity-ui/uikit';

export const SkeletonText: React.FC<{ width?: number | string; height?: number }> = ({
  width = '100%',
  height = 14,
}) => <Skeleton style={{ width, height, borderRadius: 8 }} />;
