// src/vuln/attck-mapper.js
'use strict';

/**
 * ATT&CK v15 Enterprise mapping for common service/port combinations.
 * Reference: https://attack.mitre.org/matrices/enterprise/
 *
 * Format: { tactic, tacticId, technique, techniqueId, subtechnique? }
 */
const SERVICE_ATTCK_MAP = {
  SSH: [
    { tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Brute Force', techniqueId: 'T1110', subtechnique: 'T1110.001' },
    { tactic: 'Lateral Movement',  tacticId: 'TA0008', technique: 'Remote Services: SSH', techniqueId: 'T1021', subtechnique: 'T1021.004' },
  ],
  FTP: [
    { tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Brute Force', techniqueId: 'T1110' },
    { tactic: 'Exfiltration',      tacticId: 'TA0010', technique: 'Exfiltration Over Alternative Protocol', techniqueId: 'T1048' },
  ],
  HTTP: [
    { tactic: 'Initial Access',    tacticId: 'TA0001', technique: 'Exploit Public-Facing Application', techniqueId: 'T1190' },
    { tactic: 'Discovery',         tacticId: 'TA0007', technique: 'Network Service Discovery', techniqueId: 'T1046' },
  ],
  HTTPS: [
    { tactic: 'Initial Access',    tacticId: 'TA0001', technique: 'Exploit Public-Facing Application', techniqueId: 'T1190' },
    { tactic: 'Collection',        tacticId: 'TA0009', technique: 'Adversary-in-the-Middle', techniqueId: 'T1557' },
  ],
  SMB: [
    { tactic: 'Lateral Movement',  tacticId: 'TA0008', technique: 'Remote Services: SMB/Windows Admin Shares', techniqueId: 'T1021', subtechnique: 'T1021.002' },
    { tactic: 'Credential Access', tacticId: 'TA0006', technique: 'OS Credential Dumping', techniqueId: 'T1003' },
  ],
  RDP: [
    { tactic: 'Lateral Movement',  tacticId: 'TA0008', technique: 'Remote Services: RDP', techniqueId: 'T1021', subtechnique: 'T1021.001' },
    { tactic: 'Credential Access', tacticId: 'TA0006', technique: 'Brute Force', techniqueId: 'T1110' },
  ],
  Redis: [
    { tactic: 'Initial Access',    tacticId: 'TA0001', technique: 'Exploit Public-Facing Application', techniqueId: 'T1190' },
    { tactic: 'Persistence',       tacticId: 'TA0003', technique: 'Server Software Component', techniqueId: 'T1505' },
  ],
  MongoDB: [
    { tactic: 'Collection',        tacticId: 'TA0009', technique: 'Data from Local System', techniqueId: 'T1005' },
    { tactic: 'Exfiltration',      tacticId: 'TA0010', technique: 'Exfiltration Over C2 Channel', techniqueId: 'T1041' },
  ],
};

/**
 * Map a discovered service to MITRE ATT&CK Enterprise TTPs.
 *
 * @param {string} serviceName
 * @param {number} port
 * @returns {AttckTtp[]}
 */
function mapToAttck(serviceName, port) {
  return SERVICE_ATTCK_MAP[serviceName] ?? [
    {
      tactic: 'Discovery',
      tacticId: 'TA0007',
      technique: 'Network Service Discovery',
      techniqueId: 'T1046',
      note: `Open port ${port} exposes attack surface for adversary discovery.`,
    },
  ];
}

module.exports = { mapToAttck };
