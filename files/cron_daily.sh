#!/usr/bin/env bash

. /etc/restic/env_${backup_host}

if [ -f ${LOCK_FILE} ]; then
    exit 0
fi
touch ${LOCK_FILE}

# remove old files
/opt/restic/restic forget -l ${keep.get('last', 1)} -H ${keep.get('hourly', 3)} -d ${keep.get('daily', 5)} -w ${keep.get('weekly', 2)} -m ${keep.get('monthly', 5)} -y ${keep.get('yearly', 1)} -q

# purge old files
/opt/restic/restic prune -q

rm ${LOCK_FILE}
