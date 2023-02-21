from pipes import quote
from bundlewrap.exceptions import NoSuchNode
import socket

global node, repo

RESTIC_VERSION = '0.15.1'
RESTIC_SHA256 = '3631e3c3833c84ba71f22ea3df20381676abc7476a7f6d14424d9abfada91414'


directories = {
    '/opt/restic': {
        'owner': 'root',
        'group': 'root',
        'mode': "0751",
    },
    '/etc/restic': {
        'owner': 'root',
        'group': 'root',
        'mode': "0700",
    }
}

downloads = {
    f'/opt/restic/restic_{RESTIC_VERSION}.bz2': {
        'url': f'https://github.com/restic/restic/releases/download/v{RESTIC_VERSION}/restic_{RESTIC_VERSION}'
                '_linux_amd64.bz2',
        'sha256': RESTIC_SHA256,
        'needs': ['directory:/opt/restic', 'pkg_apt:ca-certificates'],
        'triggers': ['action:unpack_restic'],
        'unless': f'test -f /opt/restic/restic_{RESTIC_VERSION}',
    }
}

actions = {
    'unpack_restic': {
        'command': f'bunzip2 -f /opt/restic/restic_{RESTIC_VERSION}.bz2 '
                    f'&& chmod +x /opt/restic/restic_{RESTIC_VERSION} '
                     '&& rm -f /opt/restic/restic '  # remove old file
                     f'&& ln -s restic_{RESTIC_VERSION} /opt/restic/restic',
        'needs': ['pkg_apt:bzip2'],
        'triggered': True,
    },
}

files = {
    '/etc/restic/include': {
        'content': "\n".join(sorted(node.metadata.get('restic', {}).get('backup_folders', []))) + "\n",
        'mode': "0600",
    },
    '/etc/restic/exclude': {
        'content': "\n".join(sorted(node.metadata.get('restic', {}).get('exclude_folders', []))) + "\n",
        'mode': "0600",
    }
}


for backup_host, backup_host_config in node.metadata.get('restic', {}).get('backup_hosts', {}).items():
    try:
        backup_node = repo.get_node(backup_host)
        backup_host = backup_node.hostname
        backup_host_ips = backup_node.metadata.get('interfaces', {}) \
            .get(backup_node.metadata.get('main_interface', 'eth0'), {}) \
            .get('ip_addresses', [])

        host_key = backup_node.metadata['openssh']['hostkey']  # This will break!!, if it is not set!
    except NoSuchNode:
        # TODO: make work without internet
        backup_host_ips = [socket.gethostbyname(backup_host), ]
        host_key = backup_host_config.get('hostkey')  # This should break, if it is not set!

    identity_file = f"~/.ssh/{backup_host}"
    port = backup_host_config.get('port', 22)

    actions[f'create_ssh_key_{backup_host}'] = {
        'command': 'ssh-keygen -t ed25519 -f ~/.ssh/{host_name} -C {comment} -N ""'.format(
            host_name=backup_host,
            comment=quote(node.name)
        ),
        'unless': f'test -f ~/.ssh/{backup_host}',
    }
    # node.download(f'/root/.ssh/{backup_host}.pub', 'test123')
    actions[f'add_ssh_config_{backup_host}'] = {
        'command': 'echo "Host {host_name}\\n'
                   'user {backup_user}\\n'
                   'identityfile {identity_file}\\n'
                   'port {port}"'
                   ' >> ~/.ssh/config'.format(
                        host_name=backup_host,
                        backup_user=backup_host_config.get('username', 'scoutnetbackup'),
                        identity_file=identity_file,
                        port=port,
                   ),
        'unless': f'grep -q \'{backup_host}\' ~/.ssh/config',
    }

    # add hostkey for hostname in known hosts file
    ssh_known_hosts_host_name = backup_host
    if port != 22:
        ssh_known_hosts_host_name = f"[{backup_host}]:{port}"

    actions[f'add_known_host_{backup_host}'] = {
        'command': 'echo {host_name} {host_key} >> ~/.ssh/known_hosts'.format(
            host_name=quote(ssh_known_hosts_host_name),
            host_key=quote(host_key)
        ),
        'unless': 'grep -q {host_name} ~/.ssh/known_hosts'.format(
            host_name=quote(ssh_known_hosts_host_name).replace('[', '\\[').replace(']', '\\]')
        ),
    }

    # add hostkey for ip in known hosts file
    for backup_host_ip in backup_host_ips:
        ssh_known_hosts_host_ip = backup_host_ip
        if port != 22:
            ssh_known_hosts_host_ip = f"[{backup_host_ip}]:{port}"

        actions[f'add_known_host_{backup_host_ip}'] = {
            'command': 'echo {host_ip} {host_key} >> ~/.ssh/known_hosts'.format(
                host_ip=quote(ssh_known_hosts_host_ip),
                host_key=quote(host_key)
            ),
            'unless': 'grep -q {host_ip} ~/.ssh/known_hosts'.format(
                host_ip=quote(ssh_known_hosts_host_ip).replace('[', '\\[').replace(']', '\\]')
            ),
        }

    actions[f'print_ssh_key_{backup_host}'] = {
        'command': 'echo "please register this ssh key on {host_name}:" && cat {identity_file}.pub && exit 255'.format(
            host_name=backup_host,
            identity_file=identity_file
        ),
        # we only allow rsync, sftp and scp
        'unless': 'ssh {host_name} rsync --server --version || false'.format(host_name=backup_host),
        'needs': [
            'action:create_ssh_key_{host_name}'.format(host_name=backup_host),
            'action:add_ssh_config_{host_name}'.format(host_name=backup_host),
            'action:add_known_host_{host_name}'.format(host_name=backup_host),
            # 'action:add_known_host_{host_ip}'.format(host_ip=backup_host_ip),
        ]
    }

    files[f'/etc/restic/password_{backup_host}'] = {
        'content': repo.vault.password_for(f"restic_password_{backup_host}_{node.name}").value,
        'owner': 'root',
        'group': 'root',
        'mode': '0600',
    }

    actions[f'init_restic_{backup_host}'] = {
        'command': '/opt/restic/restic '
                   '--password-file /etc/restic/password_{host_name} '
                   '-r sftp://{host_name}/{node_name} '
                   'init'.format(
                        host_name=backup_host,
                        node_name=node.name
                   ),
        # we only allow rsync, sftp and scp
        # try to get config file, if it is not present, we will create the repository
        'unless': f'rsync -n {backup_host}:{node.name}/config /tmp || false',
        'needs': [
            f'download:/opt/restic/restic_{RESTIC_VERSION}.bz2',
            f'action:print_ssh_key_{backup_host}',
            'action:unpack_restic',
            f'file:/etc/restic/password_{backup_host}',
        ],
    }

    # cron does not like . in filenames
    files['/etc/cron.hourly/restic_{host_name}'.format(host_name=backup_host.replace('.', '_'))] = {
        'content_type': "mako",
        'context': {
            'backup_host': backup_host,
            'node_name': node.name,
            'keep': backup_host_config.get('keep', {}),
            'pre_commands': node.metadata.get('restic', {}).get('pre_commands', []),
            'post_commands': node.metadata.get('restic', {}).get('post_commands', []),
            'stdin_commands': node.metadata.get('restic', {}).get('stdin_commands', {}),
            'LOCK_FILE': f'/tmp/restic_{backup_host}.lock',
            'RUN_HOUR': node.metadata.get('restic', {}).get('run_hour', 3),
        },
        'source': "cron_hourly.sh",
        'owner': 'root',
        'group': 'root',
        'mode': '0755',
        'needs': [
            f'action:init_restic_{backup_host}',
        ]
    }

    files['/etc/cron.daily/restic_{host_name}'.format(host_name=backup_host.replace('.', '_'))] = {
        'content_type': "mako",
        'context': {
            'backup_host': backup_host,
            'node_name': node.name,
            'keep': backup_host_config.get('keep', {}),
            'LOCK_FILE': f'/tmp/restic_{backup_host}.lock',
        },
        'source': "cron_daily.sh",
        'owner': 'root',
        'group': 'root',
        'mode': '0755',
        'needs': [
            f'action:init_restic_{backup_host}',
        ]
    }
