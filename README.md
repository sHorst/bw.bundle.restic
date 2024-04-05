Restic Bundle
-------------

This Bundle Downloads and Configures Restic (https://restic.net/).
It will pin your Backups server host key.

Needed Plugins
--------------

This Bundle needs the `download.py` item. Which you can find here: (https://github.com/sHorst/bw.item.download)

Known Problems
--------------

This plugin requires, that rsync is installed on the node. Otherwise it will try to initialise the restic repository every time.


Demo Metadata
-------------

```python
'restic': {
    'backup_hosts': {
        'backup.mydomain.net': {
            #'repository_type': 'sftp',
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
        },
        'minio.example.org': {
            'repository_type': 'minio',
            'address': 'https://localhost:9000',
            #'bucket_name': node.name,
            'environment_vars': {
                'AWS_ACCESS_KEY_ID': 'foobar',
                'AWS_SECRET_ACCESS_KEY': vault.decrypt('...').value,
            },
            'keep': {
                'last': 1,
                'hourly': 3,
                'daily': 5,
                'weekly': 2,
                'monthly': 5,
                'yearly': 1,
            }
        },
    },
    'backup_folders': [
        '/etc',
    ],
}
```
