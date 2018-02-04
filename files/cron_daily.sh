#!/usr/bin/env bash

export RESTIC_PASSWORD_FILE=/etc/restic/password_${backup_host}
export RESTIC_REPOSITORY=sftp://${backup_host}/${node_name}

# purge old files
/opt/restic/restic prune
