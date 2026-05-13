// src/enum/index.js
'use strict';

const { grabBanners } = require('./banner');
const { auditTls } = require('./tls');
const { auditHttpHeaders } = require('./http-headers');

module.exports = {
  grabBanners,
  auditTls,
  auditHttpHeaders,
};
