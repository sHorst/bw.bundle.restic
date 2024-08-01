from os.path import join, isfile
from os import system
from bundlewrap.utils import get_file_contents
from bundlewrap.exceptions import NoSuchNode, RemoteException

global metadata_reactor, node, repo

defaults = {
    'restic': {
        'version': '0.16.4',
        'checksum_sha256': '3d4d43c169a9e28ea76303b1e8b810f0dcede7478555fdaa8959971ad499e324',
        'user': 'restic',
        'group': 'restic',
        'backup_time': '*-*-* 03:00:00 UTC',
    }
}

if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {
            'rsync': {'installed': True},
            'bzip2': {'installed': True},
            'ca-certificates': {'installed': True},
        }
    }


@metadata_reactor
def load_public_keys(metadata):
    backup_hosts = {}
    for backup_host, config in metadata.get('restic/backup_hosts', {}).items():
        # Skip all none-sftp repositories
        if config.get('repository_type', 'sftp') != 'sftp':
            continue

        try:
            backup_node = repo.get_node(backup_host)
            backup_host = backup_node.hostname
            node_name = backup_node.name
        except NoSuchNode:
            node_name = backup_host

        filename = join(repo.path, 'data', 'public_keys', f'{node.name}_{backup_host}.pub')

        if not isfile(filename):
            # check if host is up
            if system("ping -c 1 -t 1 " + node.hostname) == 0:
                # download Node File
                print('\n -- needed to download new file from host, consider adding it to GIT\n')
                try:
                    node.download(f'/root/.ssh/{backup_host}.pub', filename)
                except RemoteException:
                    pass

        if isfile(filename):
            backup_hosts[node_name] = {
                'public_key': get_file_contents(filename).decode().strip(),
            }

    return {
        'restic': {
            'backup_hosts': backup_hosts,
        }
    }

# Be backward compatible and set backup_time if run_hour isn't default
@metadata_reactor
def generate_backup_time(metadata):
    run_hour = metadata.get('restic/run_hour', 3)
    if run_hour == 3:
        raise DoNotRunAgain

    return {
        'restic': {
            'backup_time': f'*-*-* {run_hour}:00:00 UTC',
        },
    }
