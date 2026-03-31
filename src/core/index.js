// src/core/index.js
'use strict';

const { ScopeGuard, ScopeViolationError } = require('./scope-guard');
const { RateLimiter } = require('./rate-limiter');
const logger = require('./logger');

module.exports = {
  ScopeGuard,
  ScopeViolationError,
  RateLimiter,
  logger,
};
