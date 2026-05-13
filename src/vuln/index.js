// src/vuln/index.js
'use strict';

const { matchVulnerabilities } = require('./vuln-matcher');
const { NvdClient } = require('./nvd-client');
const { mapToAttck } = require('./attck-mapper');

module.exports = {
  matchVulnerabilities,
  NvdClient,
  mapToAttck,
};
