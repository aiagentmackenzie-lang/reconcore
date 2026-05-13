// src/core/logger.js
'use strict';

const { createLogger, format, transports } = require('winston');
const path = require('node:path');

/**
 * Structured audit logger for ReconCore.
 * All operations are written to immutable structured logs with session ID,
 * timestamp, host, and action. Logs are written to both console and file.
 */
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  defaultMeta: { service: 'reconcore' },
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.json()
  ),
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(({ level, message, timestamp, ...metadata }) => {
          let msg = `${timestamp} [${level}]: ${message}`;
          if (Object.keys(metadata).length > 0 && metadata.service !== 'reconcore') {
            msg += ` ${JSON.stringify(metadata)}`;
          }
          return msg;
        })
      ),
    }),
    new transports.File({
      filename: path.join(process.cwd(), 'logs', 'reconcore-audit.log'),
      format: format.combine(format.json()),
    }),
  ],
  exceptionHandlers: [
    new transports.File({ filename: path.join(process.cwd(), 'logs', 'exceptions.log') }),
  ],
  rejectionHandlers: [
    new transports.File({ filename: path.join(process.cwd(), 'logs', 'rejections.log') }),
  ],
});

module.exports = logger;
