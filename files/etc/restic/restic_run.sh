#!/usr/bin/env bash

if [ -f "$LOCK_FILE" ]; then
    exit 0
fi

touch "$LOCK_FILE"

# pre backup
% for pre_cmd in pre_commands:
${pre_cmd}
% endfor

# stdin backup
% for name, cmd in sorted(stdin_commands.items()):
${cmd} | /opt/restic/restic backup -q --stdin --stdin-filename ${name}
% endfor

# backup new files
/opt/restic/restic backup -q --exclude-file /etc/restic/exclude --files-from /etc/restic/include

# post backup
% for post_cmd in post_commands:
${post_cmd}
% endfor

# remove old files
/opt/restic/restic forget -l $KEEP_LAST -H $KEEP_HOURLY -d $KEEP_DAILY -w $KEEP_WEEKLY -m $KEEP_MONTHLY -y $KEEP_YEARLY -q

rm "$LOCK_FILE"
