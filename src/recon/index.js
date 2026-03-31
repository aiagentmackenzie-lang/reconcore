// src/recon/index.js
'use strict';

const { enumerateDnsRecords, reverseDns, getNameservers, getSoaRecord } = require('./dns');
const { enumerateSubdomains } = require('./subdomain');
const { whoisLookup, asnLookup } = require('./whois');

module.exports = {
  // DNS
  enumerateDnsRecords,
  reverseDns,
  getNameservers,
  getSoaRecord,
  // Subdomain
  enumerateSubdomains,
  // WHOIS/ASN
  whoisLookup,
  asnLookup,
};
