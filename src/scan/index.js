// src/scan/index.js
'use strict';

const { scanPorts, SERVICE_MAP } = require('./port-scanner');
const { detectService, detectServices } = require('./service-detect');

module.exports = {
  scanPorts,
  SERVICE_MAP,
  detectService,
  detectServices,
};
