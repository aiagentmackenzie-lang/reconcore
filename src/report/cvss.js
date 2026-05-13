// src/report/cvss.js
'use strict';

/**
 * CVSS v3.1 severity rating scale.
 * Source: FIRST CVSS v3.1 Specification Document
 * https://www.first.org/cvss/v3.1/specification-document
 *
 * Ranges use ceiling values that overlap with the next tier's floor
 * so there are no gaps (e.g., 8.95 falls into HIGH, not NONE).
 */
const SEVERITY_RATINGS = [
  { label: 'CRITICAL', min: 9.0, max: 10.0, color: '#8B0000' },
  { label: 'HIGH',     min: 7.0, max: 9.0,  color: '#CC0000' },
  { label: 'MEDIUM',   min: 4.0, max: 7.0,  color: '#FF8C00' },
  { label: 'LOW',      min: 0.1, max: 4.0,  color: '#FFD700' },
  { label: 'NONE',     min: 0.0, max: 0.1,  color: '#6c757d' },
];

/**
 * Calculate CVSS v3.1 severity label and associated metadata from a base score.
 *
 * Uses a tiered if/else approach to guarantee no scores fall through
 * to an unexpected rating. CVSS v3.1 scores are always a single
 * decimal from 0.0–10.0, but computed values (e.g. engagement risk
 * averages) may have more decimal places.
 *
 * @param {number} baseScore - CVSS v3.1 base score (0.0 – 10.0)
 * @returns {{ label: string, color: string, baseScore: number }}
 */
function calculateSeverity(baseScore) {
  if (baseScore >= 9.0) return { label: 'CRITICAL', color: '#8B0000', baseScore };
  if (baseScore >= 7.0) return { label: 'HIGH',     color: '#CC0000', baseScore };
  if (baseScore >= 4.0) return { label: 'MEDIUM',   color: '#FF8C00', baseScore };
  if (baseScore >= 0.1) return { label: 'LOW',      color: '#FFD700', baseScore };
  return { label: 'NONE', color: '#6c757d', baseScore };
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
