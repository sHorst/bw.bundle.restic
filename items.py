from shlex import quote
from bundlewrap.exceptions import NoSuchNode
import socket

global node, repo

RESTIC_VERSION = node.metadata.get('restic').get('version')
RESTIC_SHA256 = node.metadata.get('restic').get('checksum_sha256')
RESTIC_ARCH = node.metadata.get('restic').get('arch')
RESTIC_USER = node.metadata.get('restic').get('user')
RESTIC_GROUP = node.metadata.get('restic').get('group')
RESTIC_HOME = '/etc/restic'

users = {
    RESTIC_USER: {
        'home': RESTIC_HOME,
        'shell': '/sbin/nologin',
        'password_hash': '*',
    }
}

directories = {
    '/opt/restic': {
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': "0751",
    },
    RESTIC_HOME: {
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': "0700",
    },
    f'{RESTIC_HOME}/.ssh': {
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': "0700",
    }
}

downloads = {
    f'/opt/restic/restic_{RESTIC_VERSION}.bz2': {
        'url': f'https://github.com/restic/restic/releases/download/v{RESTIC_VERSION}/'
               f'restic_{RESTIC_VERSION}_{RESTIC_ARCH}.bz2',
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
    'restic_systemd_daemon_reload': {
        'command': 'systemctl daemon-reload',
        'triggered': True,
    },
    'restic_chown_home': {
        'command': f'chown -R {RESTIC_USER}:{RESTIC_GROUP} {RESTIC_HOME}',
        'unless': f'test -z "$(find {RESTIC_HOME} ! -user {RESTIC_USER})"',
    }
}

svc_systemd = {}

files = {
    f'{RESTIC_HOME}/include': {
        'content': "\n".join(sorted(node.metadata.get('restic', {}).get('backup_folders', []))) + "\n",
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': "0600",
    },
    f'{RESTIC_HOME}/exclude': {
        'content': "\n".join(sorted(node.metadata.get('restic', {}).get('exclude_folders', []))) + "\n",
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': "0600",
    },
    '/etc/systemd/system/restic@.service': {
        'source': 'etc/systemd/system/restic@.service.j2',
        'content_type': 'jinja2',
        'context': {
            'user': RESTIC_USER,
        },
        'owner': 'root',
        'group': 'root',
        'triggers': [
            'action:restic_systemd_daemon_reload'
        ],
    },
    '/etc/systemd/system/restic@.timer': {
        'source': 'etc/systemd/system/restic@.timer.j2',
        'content_type': 'jinja2',
        'context': {
            'backup_time': node.metadata.get('restic', {}).get('backup_time'),
        },
        'owner': 'root',
        'group': 'root',
        'triggers': [
            'action:restic_systemd_daemon_reload'
        ],
    },
    '/etc/systemd/system/restic_cleanup@.service': {
        'source': 'etc/systemd/system/restic_cleanup@.service.j2',
        'content_type': 'jinja2',
        'context': {
            'user': RESTIC_USER,
        },
        'owner': 'root',
        'group': 'root',
        'triggers': [
            'action:restic_systemd_daemon_reload'
        ],
    },
    '/etc/systemd/system/restic_cleanup@.timer': {
        'source': 'etc/systemd/system/restic_cleanup@.timer.j2',
        'content_type': 'jinja2',
        'owner': 'root',
        'group': 'root',
        'triggers': [
            'action:restic_systemd_daemon_reload'
        ],
    },
    f'{RESTIC_HOME}/restic_run.sh': {
        'content_type': "mako",
        'context': {
            'pre_commands': node.metadata.get('restic', {}).get('pre_commands', []),
            'post_commands': node.metadata.get('restic', {}).get('post_commands', []),
            'stdin_commands': node.metadata.get('restic', {}).get('stdin_commands', {}),
        },
        'source': "etc/restic/restic_run.sh",
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': '0755',
        'needs': [
            f'tag:init_restic',
        ]
    },
    f'{RESTIC_HOME}/restic_cleanup.sh': {
        'source': "etc/restic/restic_cleanup.sh",
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': '0755',
        'needs': [
            f'tag:init_restic',
        ],
    },
}


for backup_host, backup_host_config in node.metadata.get('restic', {}).get('backup_hosts', {}).items():
    if backup_host_config.get('repository_type', 'sftp') in ['s3', 'minio']:
        repository_url = f"s3:{backup_host_config.get('address')}/{backup_host_config.get('bucket_name', node.name)}"
    else:  # Use sftp Repository
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

        repository_url = f'sftp://{backup_host}/{node.name}'
        identity_file = f"{RESTIC_HOME}/.ssh/{backup_host}"
        port = backup_host_config.get('port', 22)
        backup_user = backup_host_config.get('username', 'scoutnetbackup')
        comment = quote(node.name)

        actions[f'create_ssh_key_{backup_host}'] = {
                'command': f'if test -f /root/.ssh/{backup_host}; '
                           'then '
                           f'mv /root/.ssh/{backup_host} {RESTIC_HOME}/.ssh/; '
                           f'mv /root/.ssh/{backup_host}.pub {RESTIC_HOME}/.ssh/; '
                           f'chown -R {RESTIC_USER}:{RESTIC_GROUP} {RESTIC_HOME}/.ssh; '
                           'else '
                           f'sudo -u {RESTIC_USER} -H ssh-keygen -t ed25519 -f {RESTIC_HOME}/.ssh/{backup_host} '
                           f'-C {comment} -N ""; '
                           'fi',
                'needs': [f'directory:{RESTIC_HOME}/.ssh'],
                'unless': f'test -f {RESTIC_HOME}/.ssh/{backup_host}',
        }
        # node.download(f'/root/.ssh/{backup_host}.pub', 'test123')
        actions[f'add_ssh_config_{backup_host}'] = {
            'command': f'echo "Host {backup_host}\\n'
                       f'user {backup_user}\\n'
                       f'identityfile {identity_file}\\n'
                       f'port {port}"'
                       f' >> {RESTIC_HOME}/.ssh/config',
            'needs': [f'directory:{RESTIC_HOME}/.ssh'],
            'unless': f'grep -q \'{backup_host}\' {RESTIC_HOME}/.ssh/config',
        }

        # add hostkey for hostname in known hosts file
        ssh_known_hosts_host_name = backup_host
        if port != 22:
            ssh_known_hosts_host_name = f"[{backup_host}]:{port}"

        host_name = quote(ssh_known_hosts_host_name).replace('[', '\\[').replace(']', '\\]')

        actions[f'add_known_host_{backup_host}'] = {
            'command': f'echo {ssh_known_hosts_host_name} {host_key} >> {RESTIC_HOME}/.ssh/known_hosts',
            'needs': [f'directory:{RESTIC_HOME}/.ssh'],
            'unless': f'grep -q {host_name} {RESTIC_HOME}/.ssh/known_hosts',
        }

        # add hostkey for ip in known hosts file
        for backup_host_ip in backup_host_ips:
            ssh_known_hosts_host_ip = backup_host_ip
            if port != 22:
                ssh_known_hosts_host_ip = f"[{backup_host_ip}]:{port}"

            host_ip=quote(ssh_known_hosts_host_ip).replace('[', '\\[').replace(']', '\\]')

            actions[f'add_known_host_{backup_host_ip}'] = {
                'command': f'echo {ssh_known_hosts_host_ip} {host_key} >> {RESTIC_HOME}/.ssh/known_hosts',
                'needs': [f'directory:{RESTIC_HOME}/.ssh'],
                'unless': f'grep -q {host_ip} {RESTIC_HOME}/.ssh/known_hosts',
            }

        actions[f'print_ssh_key_{backup_host}'] = {
            'command': f'echo "please register this ssh key on {backup_host}:" && cat {identity_file}.pub && exit 255',
            # we only allow rsync, sftp and scp
            'unless': f'sudo -u {RESTIC_USER} ssh {backup_host} rsync --server --version || false',
            'needs': [
                'action:create_ssh_key_{host_name}'.format(host_name=backup_host),
                'action:add_ssh_config_{host_name}'.format(host_name=backup_host),
                'action:add_known_host_{host_name}'.format(host_name=backup_host),
                # 'action:add_known_host_{host_ip}'.format(host_ip=backup_host_ip),
            ],
            'tags': [
                f'prepare_restic_backup_{backup_host}',
            ]
        }

    files[f'{RESTIC_HOME}/password_{backup_host}'] = {
        'content': repo.vault.password_for(f"restic_password_{backup_host}_{node.name}").value,
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': '0600',
    }

    files[f'{RESTIC_HOME}/env_{backup_host}'] = {
        'content_type': "mako",
        'context': {
            'repository_url': repository_url,
            'backup_host': backup_host,
            'backup_host_config': backup_host_config,
        },
        'source': 'etc/restic/env_backup_host',
        'owner': RESTIC_USER,
        'group': RESTIC_GROUP,
        'mode': '0600',
    }

    actions[f'init_restic_{backup_host}'] = {
        'command': f'set -a; . {RESTIC_HOME}/env_{backup_host}; set +a && sudo -u {RESTIC_USER} -E /opt/restic/restic init',
        'unless': f'set -a; . {RESTIC_HOME}/env_{backup_host}; '
                  f'set +a && sudo -u {RESTIC_USER} -E /opt/restic/restic cat config',
        'needs': [
            f'download:/opt/restic/restic_{RESTIC_VERSION}.bz2',
            f'tag:prepare_restic_backup_{backup_host}',
            'action:unpack_restic',
            f'file:{RESTIC_HOME}/password_{backup_host}',
            f'file:{RESTIC_HOME}/env_{backup_host}',
        ],
        'tags': {
            'init_restic'
        },
    }

    svc_systemd[f'restic@{backup_host}.timer'] = {
        'enabled': True,
        'running': True,
        'triggers': [
            f'svc_systemd:restic@{backup_host}.timer:restart',
        ],
        'needs': [
            'file:/etc/systemd/system/restic@.service',
            'file:/etc/systemd/system/restic@.timer',
            'action:restic_systemd_daemon_reload',
        ],
    }
    svc_systemd[f'restic_cleanup@{backup_host}.timer'] = {
        'enabled': True,
        'running': True,
        'triggers': [
            f'svc_systemd:restic_cleanup@{backup_host}.timer:restart',
        ],
        'needs': [
            'file:/etc/systemd/system/restic_cleanup@.service',
            'file:/etc/systemd/system/restic_cleanup@.timer',
            'action:restic_systemd_daemon_reload',
        ],
    }
    files['/etc/cron.hourly/restic_{host_name}'.format(host_name=backup_host.replace('.', '_'))] = {
        'delete': True,
    }
    files['/etc/cron.daily/restic_{host_name}'.format(host_name=backup_host.replace('.', '_'))] = {
        'delete': True,
    }
