#!/usr/bin/env bash

if [ -f "$LOCK_FILE" ]; then
    exit 0
fi
touch "$LOCK_FILE"

# remove old files
/opt/restic/restic forget -l "$KEEP_LAST" -H "$KEEP_HOURLY" -d "$KEEP_DAILY" -w "$KEEP_WEEKLY" -m "$KEEP_MONTHLY" -y "$KEEP_YEARLY" -q

# purge old files
/opt/restic/restic prune -q

rm "$LOCK_FILE"
