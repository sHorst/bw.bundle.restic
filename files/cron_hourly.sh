#!/usr/bin/env bash

export RESTIC_PASSWORD_FILE=/etc/restic/password_${backup_host}
export RESTIC_REPOSITORY=sftp://${backup_host}/${node_name}

if [ -f ${LOCK_FILE} ]; then
    exit 0
fi

if [ $(date +%H) -ne ${RUN_HOUR} ]; then
    exit 0
fi

touch ${LOCK_FILE}

# pre backup
% for pre_cmd in pre_commands:
${pre_cmd}
% endfor

# stdin backup
% for name, cmd in sorted(stdin_commands.items()):
${cmd} | /opt/restic/restic backup -q --stdin --stdin-filename ${name}
% endfor

# backup new files
/opt/restic/restic backup -q --files-from /etc/restic/include

# post backup
% for post_cmd in post_commands:
${post_cmd}
% endfor

# remove old files
/opt/restic/restic forget -l ${keep.get('last', 1)} -H ${keep.get('hourly', 3)} -d ${keep.get('daily', 5)} -w ${keep.get('weekly', 2)} -m ${keep.get('monthly', 5)} -y ${keep.get('yearly', 1)} -q

rm ${LOCK_FILE}
