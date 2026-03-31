// src/report/cvss.js
'use strict';

/**
 * CVSS v3.1 severity rating scale.
 * Source: FIRST CVSS v3.1 Specification Document
 * https://www.first.org/cvss/v3.1/specification-document
 */
const SEVERITY_RATINGS = [
  { label: 'CRITICAL', min: 9.0, max: 10.0, color: '#8B0000' },
  { label: 'HIGH',     min: 7.0, max: 8.9,  color: '#CC0000' },
  { label: 'MEDIUM',   min: 4.0, max: 6.9,  color: '#FF8C00' },
  { label: 'LOW',      min: 0.1, max: 3.9,  color: '#FFD700' },
  { label: 'NONE',     min: 0.0, max: 0.0,  color: '#6c757d' },
];

/**
 * Calculate CVSS v3.1 severity label and associated metadata from a base score.
 *
 * @param {number} baseScore - CVSS v3.1 base score (0.0 – 10.0)
 * @returns {{ label: string, color: string, baseScore: number }}
 */
function calculateSeverity(baseScore) {
  const rating = SEVERITY_RATINGS.find(r => baseScore >= r.min && baseScore <= r.max)
    ?? SEVERITY_RATINGS[SEVERITY_RATINGS.length - 1];

  return { label: rating.label, color: rating.color, baseScore };
}

/**
 * Generate a severity distribution summary from a list of findings.
 *
 * @param {VulnFinding[]} findings
 * @returns {SeverityMatrix}
 */
function buildSeverityMatrix(findings) {
  const matrix = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };

  for (const finding of findings) {
    const label = finding.cvss?.severity?.label;
    if (label && label in matrix) matrix[label]++;
  }

  return { ...matrix, total: findings.length };
}

module.exports = { calculateSeverity, buildSeverityMatrix, SEVERITY_RATINGS };
