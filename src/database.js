import path from 'node:path';
import { Sequelize, DataTypes } from 'sequelize';

const storage = process.env.SQLITE_PATH || '/app/data/nekoroute.sqlite';

export const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage,
  logging: false,
  retry: { max: 3 },
  pool: { max: 1, min: 0, idle: 10000 }
});

export const ProxyNode = sequelize.define('ProxyNode', {
  id: { type: DataTypes.STRING(512), primaryKey: true },
  url: { type: DataTypes.STRING(512), allowNull: false },
  protocol: { type: DataTypes.STRING(16), allowNull: false },
  ip: { type: DataTypes.STRING(255), allowNull: false },
  port: { type: DataTypes.INTEGER, allowNull: false },
  https: { type: DataTypes.BOOLEAN, defaultValue: false },
  anonymity: { type: DataTypes.STRING(64), defaultValue: 'unknown' },
  sourceScore: { type: DataTypes.FLOAT, defaultValue: 0 },
  country: { type: DataTypes.STRING(8), defaultValue: 'XX' },
  city: { type: DataTypes.STRING(255), defaultValue: 'Unknown' },
  source: { type: DataTypes.STRING(128), defaultValue: 'Unknown' },
  region: { type: DataTypes.STRING(64), defaultValue: 'Other' },
  status: { type: DataTypes.STRING(16), defaultValue: 'unknown' },
  latencyMs: { type: DataTypes.INTEGER, allowNull: true },
  exitIp: { type: DataTypes.STRING(255), allowNull: true },
  connectionType: { type: DataTypes.STRING(32), allowNull: true },
  isVpn: { type: DataTypes.BOOLEAN, allowNull: true },
  isProxy: { type: DataTypes.BOOLEAN, allowNull: true },
  isTor: { type: DataTypes.BOOLEAN, allowNull: true },
  isHostingProvider: { type: DataTypes.BOOLEAN, allowNull: true },
  isNonResidential: { type: DataTypes.BOOLEAN, allowNull: true },
  isHomeResidential: { type: DataTypes.BOOLEAN, allowNull: true },
  ipAsn: { type: DataTypes.BIGINT, allowNull: true },
  ipOrg: { type: DataTypes.STRING(255), allowNull: true },
  ipConfidence: { type: DataTypes.STRING(32), allowNull: true },
  ipDetectionSource: { type: DataTypes.STRING(64), allowNull: true },
  ipDetectionReason: { type: DataTypes.STRING(512), allowNull: true },
  ipLookupAt: { type: DataTypes.DATE, allowNull: true },
  successes: { type: DataTypes.INTEGER, defaultValue: 0 },
  failures: { type: DataTypes.INTEGER, defaultValue: 0 },
  consecutiveFailures: { type: DataTypes.INTEGER, defaultValue: 0 },
  lastCheck: { type: DataTypes.DATE, allowNull: true },
  lastSuccess: { type: DataTypes.DATE, allowNull: true },
  lastError: { type: DataTypes.STRING(512), allowNull: true },
  firstSeen: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
  lastSeen: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
  sourcePresent: { type: DataTypes.BOOLEAN, defaultValue: true }
}, {
  tableName: 'proxy_nodes',
  timestamps: false,
  indexes: [
    { fields: ['status'] },
    { fields: ['country'] },
    { fields: ['region'] },
    { fields: ['protocol'] },
    { fields: ['lastCheck'] }
  ]
});

export const AppState = sequelize.define('AppState', {
  key: { type: DataTypes.STRING(128), primaryKey: true },
  value: { type: DataTypes.TEXT, allowNull: true }
}, { tableName: 'app_state', timestamps: false });

export const ScanResult = sequelize.define('ScanResult', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  target: { type: DataTypes.TEXT, allowNull: false },
  hostname: { type: DataTypes.STRING(255), allowNull: false },
  nodeId: { type: DataTypes.STRING(512), allowNull: true },
  country: { type: DataTypes.STRING(8), allowNull: true },
  verdict: { type: DataTypes.STRING(32), allowNull: false },
  score: { type: DataTypes.INTEGER, allowNull: false },
  statusCode: { type: DataTypes.INTEGER, allowNull: true },
  findingsJson: { type: DataTypes.TEXT, allowNull: false, defaultValue: '[]' },
  providersJson: { type: DataTypes.TEXT, allowNull: false, defaultValue: '{}' },
  scannedAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW }
}, {
  tableName: 'scan_results',
  timestamps: false,
  indexes: [{ fields: ['hostname'] }, { fields: ['scannedAt'] }]
});

const migrations = [
  {
    version: 1,
    name: 'proxy-ip-classification',
    async up(queryInterface) {
      const columns = await queryInterface.describeTable('proxy_nodes');
      const additions = [
        ['connectionType', { type: DataTypes.STRING(32), allowNull: true }],
        ['isVpn', { type: DataTypes.BOOLEAN, allowNull: true }],
        ['isProxy', { type: DataTypes.BOOLEAN, allowNull: true }],
        ['isTor', { type: DataTypes.BOOLEAN, allowNull: true }],
        ['isHostingProvider', { type: DataTypes.BOOLEAN, allowNull: true }],
        ['isNonResidential', { type: DataTypes.BOOLEAN, allowNull: true }],
        ['isHomeResidential', { type: DataTypes.BOOLEAN, allowNull: true }],
        ['ipAsn', { type: DataTypes.BIGINT, allowNull: true }],
        ['ipOrg', { type: DataTypes.STRING(255), allowNull: true }],
        ['ipConfidence', { type: DataTypes.STRING(32), allowNull: true }],
        ['ipDetectionSource', { type: DataTypes.STRING(64), allowNull: true }],
        ['ipDetectionReason', { type: DataTypes.STRING(512), allowNull: true }],
        ['ipLookupAt', { type: DataTypes.DATE, allowNull: true }]
      ];
      for (const [column, definition] of additions) {
        if (!columns[column]) await queryInterface.addColumn('proxy_nodes', column, definition);
      }
    }
  }
];

async function runMigrations() {
  const queryInterface = sequelize.getQueryInterface();
  await sequelize.query('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at DATETIME NOT NULL)');
  const [rows] = await sequelize.query('SELECT version FROM schema_migrations');
  const applied = new Set(rows.map(row => Number(row.version)));
  for (const migration of migrations.sort((a,b) => a.version - b.version)) {
    if (applied.has(migration.version)) continue;
    const transaction = await sequelize.transaction();
    try {
      await migration.up(queryInterface, transaction);
      await sequelize.query('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)', {
        replacements: [migration.version, migration.name, new Date().toISOString()],
        transaction
      });
      await transaction.commit();
      console.log('[database] migration ' + migration.version + ' applied: ' + migration.name);
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  }
}

export async function initDatabase() {
  await sequelize.authenticate();
  await sequelize.sync();
  await runMigrations();
}

export async function getState(key, fallback = null) {
  const row = await AppState.findByPk(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return row.value ?? fallback; }
}

export async function setState(key, value) {
  await AppState.upsert({ key, value: JSON.stringify(value) });
}

export async function persistNodes(nodes) {
  const rows = nodes.map(node => ({
    ...node,
    latencyMs: node.latencyMs == null ? null : Number(node.latencyMs),
    successes: Number(node.successes || 0),
    failures: Number(node.failures || 0),
    consecutiveFailures: Number(node.consecutiveFailures || 0),
    firstSeen: node.firstSeen || new Date(),
    lastSeen: node.lastSeen || new Date(),
    sourcePresent: node.sourcePresent !== false
  }));
  if (!rows.length) return;
  await ProxyNode.bulkCreate(rows, {
    updateOnDuplicate: [
      'url','protocol','ip','port','https','anonymity','sourceScore','country','city','source','region',
      'status','latencyMs','exitIp','connectionType','isVpn','isProxy','isTor','isHostingProvider','isNonResidential','isHomeResidential','ipAsn','ipOrg','ipConfidence','ipDetectionSource','ipDetectionReason','ipLookupAt','successes','failures','consecutiveFailures','lastCheck','lastSuccess',
      'lastError','firstSeen','lastSeen','sourcePresent'
    ]
  });
}

export async function saveScanResult(result) {
  await ScanResult.create({
    target: result.target,
    hostname: new URL(result.target).hostname,
    nodeId: result.nodeId || null,
    country: result.country || null,
    verdict: result.verdict,
    score: result.score,
    statusCode: result.statusCode ?? null,
    findingsJson: JSON.stringify(result.findings || []),
    providersJson: JSON.stringify(result.providers || {}),
    scannedAt: new Date()
  });
}
