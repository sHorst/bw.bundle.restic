#!/usr/bin/env bash

export RESTIC_PASSWORD_FILE=/etc/restic/password_${backup_host}
export RESTIC_REPOSITORY=sftp://${backup_host}/${node_name}

# backup new files
/opt/restic/restic backup --files-from /etc/restic/include

# remove old files
/opt/restic/restic forget -l ${keep.get('last', 1)} -H ${keep.get('hourly', 3)} -d ${keep.get('daily', 5)} -w ${keep.get('weekly', 2)} -m ${keep.get('monthly', 5)} -y ${keep.get('yearly', 1)}
