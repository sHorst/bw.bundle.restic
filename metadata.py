from os.path import join, isfile
from bundlewrap.utils import get_file_contents
from bundlewrap.exceptions import NoSuchNode

defaults = {}

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
        try:
            backup_node = repo.get_node(backup_host)
            backup_host = backup_node.hostname
            node_name = backup_node.name
        except NoSuchNode:
            node_name = backup_host

        filename = join(repo.path, 'data', 'public_keys', f'{node.name}_{backup_host}.pub')

        if not isfile(filename):
            # download Node File
            print('\n -- needed to download new file from host, consider adding it to GIT\n')
            node.download(f'/root/.ssh/{backup_host}.pub', filename)

        backup_hosts[node_name] = {
            'public_key': get_file_contents(filename).decode().strip(),
        }

    return {
        'restic': {
            'backup_hosts': backup_hosts,
        }
    }
