import React from 'react';
import { Link } from 'react-router-dom';

export const BrandLink = () => (
  <Link to="/" className="brand">
    <span className="brand-mark">ID</span>
    <span className="brand-name">UpdSpace</span>
  </Link>
);
