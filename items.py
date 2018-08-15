from pipes import quote
import socket

RESTIC_VERSION = '0.9.1'
RESTIC_SHA256 = 'f7f76812fa26ca390029216d1378e5504f18ba5dde790878dfaa84afef29bda7'


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
    '/opt/restic/restic_{version}.bz2'.format(RESTIC_VERSION): {
        'url': 'https://github.com/restic/restic/releases/download/v{version}/restic_{version}_linux_amd64.bz2'.format(
            version=RESTIC_VERSION,
        ),
        'sha256': RESTIC_SHA256,
        'needs': ['directory:/opt/restic', 'pkg_apt:ca-certificates'],
        'triggers': ['action:unpack_restic'],
        'unless': 'test -f /opt/restic/restic_{version}'.format(RESTIC_VERSION),
    }
}

actions = {
    'unpack_restic': {
        'command': 'bunzip2 -f /opt/restic/restic_{version}.bz2 '
                   '&& chmod +x /opt/restic/restic_{version} '
                   '&& rm -f /opt/restic/restic '  # remove old file
                   '&& ln -s restic_{version} /opt/restic/restic',
        'needs': ['pkg_apt:bzip2'],
        'triggered': True,
    },
}

files = {
    '/etc/restic/include': {
        'content': "\n".join(sorted(node.metadata.get('restic', {}).get('backup_folders', []))) + "\n",
        'mode': "0600",
    }
}


for backup_host, backup_host_config in node.metadata.get('restic', {}).get('backup_hosts', {}).items():
    identity_file = "~/.ssh/{host_name}".format(host_name=backup_host)
    # TODO: make work without internet
    backup_host_ip = socket.gethostbyname(backup_host)
    port = backup_host_config.get('port', 22)
    host_key = backup_host_config.get('hostkey')  # This should break, if it is not set!

    actions['create_ssh_key_{host_name}'.format(host_name=backup_host)] = {
        'command': 'ssh-keygen -t ed25519 -f ~/.ssh/{host_name} -C {comment} -N ""'.format(
            host_name=backup_host,
            comment=quote(node.name)
        ),
        'unless': 'test -f ~/.ssh/{host_name}'.format(host_name=backup_host),
    }
    actions['add_ssh_config_{host_name}'.format(host_name=backup_host)] = {
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
        'unless': 'grep -q \'{host_name}\' ~/.ssh/config'.format(host_name=backup_host),
    }

    # add hostkey for hostname in known hosts file
    ssh_known_hosts_host_name = backup_host
    if port != 22:
        ssh_known_hosts_host_name = "[{host_name}]:{port}".format(host_name=backup_host, port=port)

    actions['add_known_host_{host_name}'.format(host_name=backup_host)] = {
        'command': 'echo {host_name} {host_key} >> ~/.ssh/known_hosts'.format(
            host_name=quote(ssh_known_hosts_host_name),
            host_key=quote(host_key)
        ),
        'unless': 'grep -q {host_name} ~/.ssh/known_hosts'.format(
            host_name=quote(ssh_known_hosts_host_name).replace('[', '\\[').replace(']', '\\]')
        ),
    }

    # add hostkey for ip in known hosts file
    ssh_known_hosts_host_ip = backup_host_ip
    if port != 22:
        ssh_known_hosts_host_ip = "[{host_ip}]:{port}".format(host_ip=backup_host_ip, port=port)

    actions['add_known_host_{host_ip}'.format(host_ip=backup_host_ip)] = {
        'command': 'echo {host_ip} {host_key} >> ~/.ssh/known_hosts'.format(
            host_ip=quote(ssh_known_hosts_host_ip),
            host_key=quote(host_key)
        ),
        'unless': 'grep -q {host_ip} ~/.ssh/known_hosts'.format(
            host_ip=quote(ssh_known_hosts_host_ip).replace('[', '\\[').replace(']', '\\]')
        ),
    }

    # TODO: ipv6
    actions['print_ssh_key_{host_name}'.format(host_name=backup_host)] = {
        'command': 'echo "please register this ssh key on {host_name}:" && cat {identity_file}.pub && exit 255'.format(
            host_name=backup_host,
            identity_file=identity_file
        ),
        # we only allow rsync, sftp and scp
        'unless': 'ssh -4 {host_name} rsync --version || false'.format(host_name=backup_host),
        'needs': [
            'action:create_ssh_key_{host_name}'.format(host_name=backup_host),
            'action:add_ssh_config_{host_name}'.format(host_name=backup_host),
            'action:add_known_host_{host_name}'.format(host_name=backup_host),
            'action:add_known_host_{host_ip}'.format(host_ip=backup_host_ip),
        ]
    }

    files['/etc/restic/password_{host_name}'.format(host_name=backup_host)] = {
        'content': repo.libs.pw.get("restic_password_{host_name}_{node_name}".format(
            host_name=backup_host,
            node_name=node.name
        )),
        'owner': 'root',
        'group': 'root',
        'mode': '0600',
    }

    actions['init_restic_{host_name}'.format(host_name=backup_host)] = {
        'command': '/opt/restic/restic '
                   '--password-file /etc/restic/password_{host_name} '
                   '-r sftp://{host_name}/{node_name} '
                   'init'.format(
                        host_name=backup_host,
                        node_name=node.name
                   ),
        # we only allow rsync, sftp and scp
        'unless': 'ssh -4 {host_name} rsync {node_name}/config || false'.format(
                      host_name=backup_host,
                      node_name=node.name,
                   ),
        'needs': [
            'download:/opt/restic/restic.bz2',
            'action:print_ssh_key_{host_name}'.format(host_name=backup_host),
            'action:unpack_restic',
            'file:/etc/restic/password_{host_name}'.format(host_name=backup_host),
        ]
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
            'LOCK_FILE': '/tmp/restic.lock',
        },
        'source': "cron_hourly.sh",
        'owner': 'root',
        'group': 'root',
        'mode': '0755',
        'needs': [
            'action:init_restic_{host_name}'.format(host_name=backup_host),
        ]
    }

    files['/etc/cron.daily/restic_{host_name}'.format(host_name=backup_host.replace('.', '_'))] = {
        'content_type': "mako",
        'context': {
            'backup_host': backup_host,
            'node_name': node.name,
            'keep': backup_host_config.get('keep', {}),
        },
        'source': "cron_daily.sh",
        'owner': 'root',
        'group': 'root',
        'mode': '0755',
        'needs': [
            'action:init_restic_{host_name}'.format(host_name=backup_host),
        ]
    }
