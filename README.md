Restic Bundle
-------------

This Bundle Downloads and Configures Restic (https://restic.net/). 
It will pin your Backups server host key.

Needed Plugins
--------------

This Bundle needs the `download.py` item. Which you can find here: (https://github.com/sHorst/bw.item.download)


Demo Metadata
-------------

```python
'restic': {
    'backup_hosts': {
        'backup.mydomain.net': {
            'username': 'myBackupUser',
            'port': 12345,
            'hostkey': 'ecdsa-sha2-nistp256 ...',
            'keep': {
                'last': 1,
                'hourly': 3,
                'daily': 5,
                'weekly': 2,
                'monthly': 5,
                'yearly': 1,
            }
        }
    },
    'backup_folders': [
        '/etc'
    ],
}
```
