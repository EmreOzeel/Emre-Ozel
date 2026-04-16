#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# PCAP Analyzer — PostgreSQL Backup Script
# ══════════════════════════════════════════════════════════════════════════════
#
# Dumps the PostgreSQL database to a gzipped SQL file and removes backups
# older than 7 days.
#
# Intended to be run via cron (install.sh sets this up automatically):
#   0 2 * * * /opt/pcap-analyzer/scripts/backup.sh >> /var/log/pcap-backup.log 2>&1
#
# Can also be run manually:
#   bash /opt/pcap-analyzer/scripts/backup.sh
#
set -euo pipefail

INSTALL_DIR="/opt/pcap-analyzer"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.prod.yml"
BACKUP_DIR="$INSTALL_DIR/backups"
RETENTION_DAYS=7

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="pcap_backup_${TIMESTAMP}.sql.gz"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

echo "[$(date -Iseconds)] Starting backup..."

# Dump PostgreSQL database via Docker
docker compose -f "$COMPOSE_FILE" exec -T postgres \
    pg_dump -U pcap pcap_analyzer \
    | gzip > "$BACKUP_DIR/$BACKUP_FILE"

# Verify the backup is not empty
FILESIZE=$(stat -c%s "$BACKUP_DIR/$BACKUP_FILE" 2>/dev/null || stat -f%z "$BACKUP_DIR/$BACKUP_FILE" 2>/dev/null || echo "0")
if [ "$FILESIZE" -lt 100 ]; then
    echo "[$(date -Iseconds)] ERROR: Backup file is suspiciously small (${FILESIZE} bytes). Check database connectivity."
    rm -f "$BACKUP_DIR/$BACKUP_FILE"
    exit 1
fi

echo "[$(date -Iseconds)] Backup completed: $BACKUP_FILE ($(( FILESIZE / 1024 )) KB)"

# Remove backups older than retention period
DELETED=$(find "$BACKUP_DIR" -name "pcap_backup_*.sql.gz" -mtime +${RETENTION_DAYS} -delete -print | wc -l)
if [ "$DELETED" -gt 0 ]; then
    echo "[$(date -Iseconds)] Cleaned up $DELETED backup(s) older than ${RETENTION_DAYS} days."
fi

# List remaining backups
REMAINING=$(find "$BACKUP_DIR" -name "pcap_backup_*.sql.gz" | wc -l)
echo "[$(date -Iseconds)] Total backups on disk: $REMAINING"
