// src/report/index.js
'use strict';

const { calculateSeverity, buildSeverityMatrix, SEVERITY_RATINGS } = require('./cvss');
const { generateReport } = require('./reporter');

module.exports = {
  calculateSeverity,
  buildSeverityMatrix,
  SEVERITY_RATINGS,
  generateReport,
};
