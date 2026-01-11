"""
SSH Honeypot - Fake SSH Server
Captures credentials and commands from attackers using Paramiko
Enhanced with realistic rule-based responses
"""

import os
import sys
import socket
import threading
import uuid
import random
import re
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Tuple

try:
    import paramiko
    from paramiko import RSAKey
except ImportError:
    print("Error: paramiko is required. Install with: pip install paramiko")
    sys.exit(1)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Rule-based patterns for suspicious command detection
SUSPICIOUS_PATTERNS = {
    'crypto_miner': [
        r'xmrig', r'minerd', r'cpuminer', r'cgminer', r'bfgminer',
        r'stratum\+tcp', r'pool\.', r'nicehash', r'monero',
    ],
    'botnet': [
        r'\.sh\s*\|\s*bash', r'curl.*\|.*sh', r'wget.*\|.*sh',
        r'/tmp/\.', r'chmod\s+777', r'nohup.*&',
    ],
    'backdoor': [
        r'nc\s+-[el]', r'netcat', r'/dev/tcp/', r'mkfifo',
        r'reverse.*shell', r'bind.*shell',
    ],
    'recon': [
        r'cat\s+/etc/passwd', r'cat\s+/etc/shadow', r'find.*-perm',
        r'ps\s+aux', r'netstat', r'ss\s+-', r'lsof',
    ],
    'persistence': [
        r'crontab', r'/etc/cron', r'\.bashrc', r'\.profile',
        r'authorized_keys', r'systemctl\s+enable',
    ],
}


def classify_command(command: str) -> List[str]:
    """Classify a command into threat categories using rule-based matching"""
    categories = []
    cmd_lower = command.lower()
    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, cmd_lower):
                categories.append(category)
                break
    return categories


class FakeShell:
    """Fake shell environment for SSH honeypot with realistic rule-based responses"""

    # System profiles for different honeypot personas
    SYSTEM_PROFILES = {
        'ubuntu_server': {
            'hostname': 'ubuntu-server',
            'os_name': 'Ubuntu 22.04.3 LTS',
            'kernel': '5.15.0-91-generic',
            'arch': 'x86_64',
        },
        'debian': {
            'hostname': 'debian-host',
            'os_name': 'Debian GNU/Linux 12 (bookworm)',
            'kernel': '6.1.0-17-amd64',
            'arch': 'x86_64',
        },
        'centos': {
            'hostname': 'centos-server',
            'os_name': 'CentOS Stream release 9',
            'kernel': '5.14.0-391.el9.x86_64',
            'arch': 'x86_64',
        },
    }

    def __init__(self, username: str, profile: str = 'ubuntu_server'):
        self.username = username
        self.profile = self.SYSTEM_PROFILES.get(profile, self.SYSTEM_PROFILES['ubuntu_server'])
        self.hostname = self.profile['hostname']
        self.cwd = '/home/' + username if username != 'root' else '/root'
        self.start_time = datetime.now()
        self.boot_time = datetime.now() - timedelta(days=random.randint(1, 30),
                                                     hours=random.randint(0, 23),
                                                     minutes=random.randint(0, 59))
        self.command_history = []
        self.sudo_authenticated = False
        self.created_files = {}
        self.created_dirs = set()

        self.env = {
            'USER': username,
            'HOME': self.cwd,
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'SHELL': '/bin/bash',
            'TERM': 'xterm-256color',
            'LANG': 'en_US.UTF-8',
            'HOSTNAME': self.hostname,
        }

        # Comprehensive fake filesystem structure
        self.filesystem = {
            # Root directories
            '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64', 'media', 'mnt',
                  'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],

            # Boot
            '/boot': ['grub', 'vmlinuz', 'initrd.img', 'config-5.15.0-91-generic'],
            '/boot/grub': ['grub.cfg', 'grubenv'],

            # Home directories
            '/home': ['admin', 'user', 'ubuntu', 'deploy', 'www-data'],
            '/home/admin': ['.bashrc', '.profile', '.bash_history', '.ssh', '.vimrc',
                           '.gitconfig', 'documents', 'scripts', 'projects', 'Downloads'],
            '/home/admin/.ssh': ['authorized_keys', 'known_hosts', 'id_rsa', 'id_rsa.pub', 'config'],
            '/home/admin/documents': ['readme.txt', 'notes.txt', 'passwords.txt', 'todo.md', 'budget.xlsx'],
            '/home/admin/scripts': ['backup.sh', 'deploy.sh', 'cleanup.sh', 'monitor.py', 'cron_jobs.sh'],
            '/home/admin/projects': ['webapp', 'api-server', 'scripts'],
            '/home/admin/projects/webapp': ['app.py', 'config.py', 'requirements.txt', '.env', 'README.md'],
            '/home/admin/projects/api-server': ['server.js', 'package.json', '.env', 'config.json'],
            '/home/admin/Downloads': ['backup_2024.tar.gz', 'mysql_dump.sql', 'config_backup.zip'],
            '/home/user': ['.bashrc', '.profile', '.bash_history', 'notes.txt'],
            '/home/ubuntu': ['.bashrc', '.profile', '.bash_history', '.sudo_as_admin_successful', '.ssh'],
            '/home/ubuntu/.ssh': ['authorized_keys'],
            '/home/deploy': ['.bashrc', '.profile', '.ssh', 'app', 'logs', 'releases'],
            '/home/deploy/.ssh': ['authorized_keys', 'deploy_key'],
            '/home/deploy/app': ['current', 'shared', 'releases'],
            '/home/deploy/app/current': ['app.py', 'config.py', '.env', 'requirements.txt'],
            '/home/deploy/app/shared': ['uploads', 'logs', 'config'],
            '/home/deploy/logs': ['app.log', 'error.log', 'access.log'],
            '/home/www-data': ['.bashrc', 'html'],

            # Root home
            '/root': ['.bashrc', '.profile', '.ssh', '.bash_history', '.vimrc',
                     '.mysql_history', 'scripts', 'backups', '.credentials'],
            '/root/.ssh': ['authorized_keys', 'id_rsa', 'id_rsa.pub', 'known_hosts', 'config'],
            '/root/scripts': ['backup.sh', 'firewall.sh', 'deploy.sh', 'monitor.sh', 'rotate_logs.sh'],
            '/root/backups': ['db_backup_2024.sql.gz', 'config_backup.tar.gz', 'home_backup.tar.gz'],

            # Etc configurations
            '/etc': ['passwd', 'shadow', 'group', 'gshadow', 'hosts', 'hostname', 'resolv.conf',
                    'ssh', 'nginx', 'apache2', 'mysql', 'redis', 'crontab', 'sudoers', 'sudoers.d',
                    'os-release', 'issue', 'motd', 'fstab', 'network', 'netplan', 'systemd',
                    'ssl', 'security', 'pam.d', 'profile', 'profile.d', 'bash.bashrc',
                    'apt', 'default', 'init.d', 'logrotate.d', 'cron.d', 'cron.daily'],
            '/etc/ssh': ['sshd_config', 'ssh_config', 'ssh_host_rsa_key', 'ssh_host_rsa_key.pub',
                        'ssh_host_ecdsa_key', 'ssh_host_ecdsa_key.pub', 'moduli'],
            '/etc/nginx': ['nginx.conf', 'sites-available', 'sites-enabled', 'conf.d', 'snippets'],
            '/etc/nginx/sites-available': ['default', 'example.com', 'api.example.com'],
            '/etc/nginx/sites-enabled': ['default', 'example.com'],
            '/etc/nginx/conf.d': ['ssl.conf', 'security.conf'],
            '/etc/apache2': ['apache2.conf', 'sites-available', 'sites-enabled', 'mods-enabled'],
            '/etc/apache2/sites-available': ['000-default.conf', 'default-ssl.conf'],
            '/etc/mysql': ['my.cnf', 'mysql.conf.d', 'debian.cnf'],
            '/etc/mysql/mysql.conf.d': ['mysqld.cnf'],
            '/etc/redis': ['redis.conf'],
            '/etc/network': ['interfaces', 'if-up.d', 'if-down.d'],
            '/etc/netplan': ['01-netcfg.yaml', '50-cloud-init.yaml'],
            '/etc/systemd': ['system', 'user'],
            '/etc/systemd/system': ['multi-user.target.wants', 'nginx.service', 'mysql.service'],
            '/etc/ssl': ['certs', 'private', 'openssl.cnf'],
            '/etc/ssl/certs': ['ca-certificates.crt'],
            '/etc/ssl/private': ['server.key', 'server.crt', 'dhparam.pem'],
            '/etc/sudoers.d': ['admin', 'deploy'],
            '/etc/cron.d': ['certbot', 'php', 'backup'],
            '/etc/cron.daily': ['apt-compat', 'logrotate', 'man-db', 'backup'],

            # Tmp - attackers often use this
            '/tmp': ['.X11-unix', '.ICE-unix', 'systemd-private-xxx'],

            # Var directories
            '/var': ['log', 'www', 'lib', 'cache', 'mail', 'spool', 'run', 'tmp', 'backups'],
            '/var/log': ['syslog', 'auth.log', 'kern.log', 'messages', 'dmesg', 'dpkg.log',
                        'nginx', 'apache2', 'mysql', 'redis', 'fail2ban.log', 'lastlog',
                        'wtmp', 'btmp', 'ufw.log', 'alternatives.log', 'bootstrap.log'],
            '/var/log/nginx': ['access.log', 'error.log', 'access.log.1', 'error.log.1'],
            '/var/log/apache2': ['access.log', 'error.log', 'other_vhosts_access.log'],
            '/var/log/mysql': ['error.log', 'mysql.log', 'slow-query.log'],
            '/var/www': ['html', 'example.com', 'api.example.com'],
            '/var/www/html': ['index.html', 'index.php', 'info.php', 'robots.txt', '.htaccess',
                             'wp-config.php', 'uploads', 'wp-content'],
            '/var/www/html/uploads': ['images', 'files', 'documents'],
            '/var/www/html/wp-content': ['themes', 'plugins', 'uploads'],
            '/var/www/example.com': ['public_html', 'logs', 'ssl'],
            '/var/www/example.com/public_html': ['index.php', '.env', 'config.php', 'storage', 'vendor'],
            '/var/lib': ['mysql', 'redis', 'docker', 'apt', 'dpkg'],
            '/var/lib/mysql': ['mysql', 'performance_schema', 'sys', 'wordpress', 'app_production'],
            '/var/backups': ['apt.extended_states.0', 'dpkg.status.0', 'passwd.bak', 'shadow.bak'],

            # Usr directories
            '/usr': ['bin', 'sbin', 'lib', 'lib64', 'local', 'share', 'include', 'src'],
            '/usr/bin': ['python3', 'python3.10', 'pip3', 'node', 'npm', 'php', 'php8.1',
                        'java', 'javac', 'gcc', 'g++', 'make', 'cmake', 'git', 'curl', 'wget',
                        'vim', 'nano', 'htop', 'tmux', 'screen', 'docker', 'docker-compose'],
            '/usr/sbin': ['nginx', 'apache2', 'mysqld', 'sshd', 'cron', 'rsyslogd', 'ufw'],
            '/usr/local': ['bin', 'lib', 'share', 'etc', 'src'],
            '/usr/local/bin': ['docker-compose', 'node', 'npm', 'composer'],
            '/usr/share': ['doc', 'man', 'nginx', 'apache2', 'mysql'],

            # Opt - third party applications
            '/opt': ['scripts', 'apps', 'backups', 'lampp'],
            '/opt/scripts': ['deploy.sh', 'backup_db.sh', 'monitor.py', 'cleanup.sh'],
            '/opt/apps': ['myapp', 'api'],
            '/opt/apps/myapp': ['app.py', 'config.py', '.env', 'requirements.txt', 'logs'],
            '/opt/apps/api': ['server.js', 'package.json', '.env', 'node_modules'],

            # Proc - system info
            '/proc': ['cpuinfo', 'meminfo', 'version', 'uptime', 'loadavg', 'mounts',
                     'net', 'sys', 'self', '1', 'cmdline', 'filesystems'],
            '/proc/net': ['tcp', 'udp', 'route', 'arp', 'dev'],

            # Dev devices
            '/dev': ['null', 'zero', 'random', 'urandom', 'tty', 'tty0', 'tty1', 'console',
                    'sda', 'sda1', 'sda2', 'sr0', 'loop0', 'loop1', 'pts', 'shm'],
            '/dev/pts': ['0', '1', 'ptmx'],

            # Srv - service data
            '/srv': ['ftp', 'www', 'git'],
            '/srv/www': ['htdocs'],

            # Run - runtime data
            '/run': ['lock', 'user', 'sshd', 'nginx', 'mysqld', 'docker', 'systemd'],
            '/run/sshd': [],
            '/run/mysqld': ['mysqld.sock', 'mysqld.pid'],
        }

        # Realistic fake file contents
        self.file_contents = {
            # System files
            '/etc/passwd': self._generate_passwd(),
            '/etc/shadow': self._generate_shadow(),
            '/etc/group': self._generate_group(),
            '/etc/hosts': '127.0.0.1\tlocalhost\n127.0.1.1\t' + self.hostname + '\n\n' +
                         '# The following lines are desirable for IPv6 capable hosts\n' +
                         '::1     localhost ip6-localhost ip6-loopback\n' +
                         'ff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n\n' +
                         '# Internal servers\n' +
                         '192.168.1.10\tdb.internal\n' +
                         '192.168.1.20\tapi.internal\n',
            '/etc/hostname': self.hostname + '\n',
            '/etc/resolv.conf': '# Generated by NetworkManager\n' +
                               'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' +
                               'search example.com\n',
            '/etc/os-release': f'NAME="{self.profile["os_name"].split()[0]}"\n' +
                              f'VERSION="{self.profile["os_name"]}"\n' +
                              f'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="{self.profile["os_name"]}"\n' +
                              'VERSION_ID="22.04"\nHOME_URL="https://www.ubuntu.com/"\n',
            '/etc/issue': f'{self.profile["os_name"]} \\n \\l\n\n',
            '/etc/motd': '',
            '/etc/fstab': '# /etc/fstab: static file system information.\n' +
                         '# <file system> <mount point> <type> <options> <dump> <pass>\n' +
                         'UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 / ext4 errors=remount-ro 0 1\n' +
                         'UUID=b2c3d4e5-f6a7-8901-bcde-f12345678901 /home ext4 defaults 0 2\n' +
                         '/swapfile none swap sw 0 0\n',
            '/etc/sudoers': '# User privilege specification\n' +
                           'root\tALL=(ALL:ALL) ALL\n' +
                           '%admin ALL=(ALL) ALL\n' +
                           '%sudo\tALL=(ALL:ALL) ALL\n' +
                           'admin\tALL=(ALL) NOPASSWD: ALL\n',

            # SSH configs
            '/etc/ssh/sshd_config': self._generate_sshd_config(),
            '/etc/ssh/ssh_config': '# SSH client configuration\n' +
                                  'Host *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n',

            # Nginx configs
            '/etc/nginx/nginx.conf': self._generate_nginx_conf(),
            '/etc/nginx/sites-available/default': self._generate_nginx_site(),
            '/etc/nginx/sites-available/example.com': self._generate_nginx_site('example.com'),

            # MySQL configs
            '/etc/mysql/my.cnf': '[mysqld]\nuser = mysql\npid-file = /run/mysqld/mysqld.pid\n' +
                                'socket = /run/mysqld/mysqld.sock\nport = 3306\n' +
                                'datadir = /var/lib/mysql\n',
            '/etc/mysql/debian.cnf': '# Automatically generated - DO NOT EDIT\n' +
                                    '[client]\nhost = localhost\nuser = debian-sys-maint\n' +
                                    'password = Kj8sD9fLm2nP4qRt\nsocket = /run/mysqld/mysqld.sock\n',

            # Cron
            '/etc/crontab': '# /etc/crontab: system-wide crontab\n' +
                           'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n\n' +
                           '# m h dom mon dow user command\n' +
                           '17 * * * * root cd / && run-parts --report /etc/cron.hourly\n' +
                           '25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n' +
                           '0 */6 * * * root /opt/scripts/backup_db.sh\n' +
                           '*/5 * * * * www-data /var/www/html/cron.php\n',

            # Proc filesystem
            '/proc/version': f'Linux version {self.profile["kernel"]} (build@host) ' +
                            f'(gcc version 11.4.0) #1 SMP PREEMPT_DYNAMIC\n',
            '/proc/cpuinfo': self._generate_cpuinfo(),
            '/proc/meminfo': self._generate_meminfo(),
            '/proc/cmdline': 'BOOT_IMAGE=/boot/vmlinuz-5.15.0-91-generic root=UUID=a1b2c3d4 ro quiet splash\n',
            '/proc/mounts': '/dev/sda1 / ext4 rw,relatime 0 0\n' +
                           '/dev/sda2 /home ext4 rw,relatime 0 0\n' +
                           'tmpfs /run tmpfs rw,nosuid,nodev 0 0\n' +
                           'proc /proc proc rw,nosuid,nodev,noexec 0 0\n',

            # Log files
            '/var/log/auth.log': self._generate_auth_log(),
            '/var/log/syslog': self._generate_syslog(),
            '/var/log/nginx/access.log': self._generate_nginx_access_log(),
            '/var/log/nginx/error.log': self._generate_nginx_error_log(),

            # Web files
            '/var/www/html/index.html': '<!DOCTYPE html>\n<html>\n<head>\n    <title>Welcome to nginx!</title>\n' +
                                       '</head>\n<body>\n<h1>Welcome to nginx!</h1>\n' +
                                       '<p>If you see this page, nginx is installed and working.</p>\n' +
                                       '</body>\n</html>\n',
            '/var/www/html/index.php': '<?php\nphpinfo();\n?>\n',
            '/var/www/html/robots.txt': 'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config/\n',
            '/var/www/html/.htaccess': 'RewriteEngine On\nRewriteCond %{HTTPS} off\n' +
                                      'RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n',
            '/var/www/html/wp-config.php': self._generate_wp_config(),
            '/var/www/example.com/public_html/.env': self._generate_env_file(),
            '/var/www/example.com/public_html/config.php': self._generate_php_config(),

            # Home directory files
            '/home/admin/.bashrc': self._generate_bashrc(),
            '/home/admin/.bash_history': self._generate_bash_history(),
            '/home/admin/.gitconfig': '[user]\n    name = Admin User\n    email = admin@example.com\n' +
                                     '[core]\n    editor = vim\n',
            '/home/admin/.ssh/config': 'Host github.com\n    HostName github.com\n    User git\n    IdentityFile ~/.ssh/id_rsa\n\n' +
                                      'Host production\n    HostName 192.168.1.100\n    User deploy\n    IdentityFile ~/.ssh/deploy_key\n',
            '/home/admin/.ssh/authorized_keys': 'ssh-rsa AAAAB3NzaC1yc2EAAAA... admin@workstation\n',
            '/home/admin/.ssh/id_rsa': self._generate_fake_private_key(),
            '/home/admin/.ssh/id_rsa.pub': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... admin@' + self.hostname + '\n',
            '/home/admin/documents/passwords.txt': self._generate_fake_passwords(),
            '/home/admin/documents/notes.txt': 'Meeting notes:\n- Deploy new version Friday\n' +
                                              '- Update SSL certificates before Dec 31\n' +
                                              '- Database migration scheduled for weekend\n\n' +
                                              'TODO:\n- Fix login bug\n- Update dependencies\n',
            '/home/admin/documents/readme.txt': 'Project Documentation\n' + '='*50 + '\n\n' +
                                               'Server: ' + self.hostname + '\n' +
                                               'Environment: Production\n' +
                                               'Maintainer: admin@example.com\n',
            '/home/admin/projects/webapp/.env': 'APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:Xk2d8f9...\n' +
                                               'DB_HOST=localhost\nDB_DATABASE=webapp\nDB_USERNAME=webapp_user\n' +
                                               'DB_PASSWORD=Pr0d_P@ssw0rd_2024!\n\n' +
                                               'REDIS_HOST=127.0.0.1\nREDIS_PORT=6379\n',
            '/home/admin/projects/api-server/.env': 'NODE_ENV=production\nPORT=3000\n' +
                                                   'DATABASE_URL=mysql://api_user:S3cr3t_API_P@ss@localhost/api_db\n' +
                                                   'JWT_SECRET=super_secret_jwt_key_2024\n' +
                                                   'API_KEY=sk_live_abc123def456ghi789\n',
            '/home/admin/scripts/backup.sh': self._generate_backup_script(),
            '/home/admin/scripts/deploy.sh': self._generate_deploy_script(),

            # Root files
            '/root/.bashrc': self._generate_bashrc(),
            '/root/.bash_history': self._generate_root_bash_history(),
            '/root/.mysql_history': 'SELECT * FROM users;\nSHOW DATABASES;\n' +
                                   'UPDATE users SET password="hash" WHERE id=1;\n' +
                                   'GRANT ALL PRIVILEGES ON *.* TO "admin"@"localhost";\n',
            '/root/.ssh/authorized_keys': 'ssh-rsa AAAAB3NzaC1yc2EAAAA... root@backup-server\n',
            '/root/.ssh/id_rsa': self._generate_fake_private_key(),
            '/root/.credentials': '# Database credentials\n' +
                                 'MYSQL_ROOT_PASSWORD=R00t_MySQL_P@ss!\n' +
                                 'REDIS_PASSWORD=r3d1s_s3cr3t\n\n' +
                                 '# API Keys\n' +
                                 'AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n' +
                                 'AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n',
            '/root/scripts/backup.sh': self._generate_backup_script(),
            '/root/scripts/firewall.sh': '#!/bin/bash\n# Firewall rules\n' +
                                        'iptables -F\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\n' +
                                        'iptables -A INPUT -p tcp --dport 80 -j ACCEPT\n' +
                                        'iptables -A INPUT -p tcp --dport 443 -j ACCEPT\n',

            # Deploy user files
            '/home/deploy/app/current/.env': 'APP_ENV=production\nAPP_KEY=base64:productionkey...\n' +
                                            'DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n' +
                                            'DB_DATABASE=app_production\nDB_USERNAME=app_user\n' +
                                            'DB_PASSWORD=D3pl0y_DB_P@ssw0rd\n',

            # Opt scripts
            '/opt/scripts/backup_db.sh': '#!/bin/bash\n# Database backup script\n' +
                                        'MYSQL_PWD="R00t_MySQL_P@ss!" mysqldump -u root --all-databases > /opt/backups/db_$(date +%Y%m%d).sql\n' +
                                        'gzip /opt/backups/db_$(date +%Y%m%d).sql\n',
            '/opt/apps/myapp/.env': 'DEBUG=false\nSECRET_KEY=django-insecure-abc123xyz\n' +
                                   'DATABASE_URL=postgres://myapp:MyApp_DB_Pass@localhost/myapp_prod\n',
        }

    def _generate_passwd(self) -> str:
        """Generate realistic /etc/passwd content"""
        lines = [
            'root:x:0:0:root:/root:/bin/bash',
            'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
            'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
            'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
            'sync:x:4:65534:sync:/bin:/bin/sync',
            'games:x:5:60:games:/usr/games:/usr/sbin/nologin',
            'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin',
            'lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin',
            'mail:x:8:8:mail:/var/mail:/usr/sbin/nologin',
            'news:x:9:9:news:/var/spool/news:/usr/sbin/nologin',
            'uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin',
            'proxy:x:13:13:proxy:/bin:/usr/sbin/nologin',
            'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
            'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin',
            'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
            'sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin',
            'admin:x:1000:1000:Administrator:/home/admin:/bin/bash',
            'ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash',
            'user:x:1002:1002::/home/user:/bin/bash',
            'deploy:x:1003:1003:Deploy User:/home/deploy:/bin/bash',
            'mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false',
            'postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/false',
        ]
        return '\n'.join(lines) + '\n'

    def _generate_cpuinfo(self) -> str:
        """Generate realistic /proc/cpuinfo"""
        return '''processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) CPU @ 2.20GHz
stepping	: 7
microcode	: 0x1
cpu MHz		: 2199.998
cache size	: 56320 KB
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 2
fpu		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc
bogomips	: 4399.99
'''

    def _generate_meminfo(self) -> str:
        """Generate realistic /proc/meminfo"""
        total = random.randint(4, 16) * 1024 * 1024  # 4-16 GB in KB
        free = random.randint(int(total * 0.2), int(total * 0.5))
        available = random.randint(free, int(total * 0.7))
        buffers = random.randint(100000, 500000)
        cached = random.randint(500000, 2000000)
        return f'''MemTotal:       {total} kB
MemFree:        {free} kB
MemAvailable:   {available} kB
Buffers:        {buffers} kB
Cached:         {cached} kB
SwapTotal:      2097148 kB
SwapFree:       2097148 kB
'''

    def _generate_auth_log(self) -> str:
        """Generate realistic auth.log entries"""
        now = datetime.now()
        lines = []
        for i in range(10, 0, -1):
            t = now - timedelta(minutes=i*5)
            timestamp = t.strftime('%b %d %H:%M:%S')
            ip = f"192.168.1.{random.randint(1, 254)}"
            lines.append(f"{timestamp} {self.hostname} sshd[{random.randint(1000, 9999)}]: " +
                        f"Failed password for invalid user admin from {ip} port {random.randint(40000, 65000)} ssh2")
        lines.append(f"{now.strftime('%b %d %H:%M:%S')} {self.hostname} sshd[{random.randint(1000, 9999)}]: " +
                    f"Accepted password for {self.username} from 10.0.0.1 port 22 ssh2")
        return '\n'.join(lines) + '\n'

    def _generate_shadow(self) -> str:
        """Generate realistic /etc/shadow content"""
        return '''root:$6$rounds=4096$xYzAbCdEfG$hAsHeD.pAsSwOrD.HeRe.VeRyLoNg:19723:0:99999:7:::
daemon:*:19723:0:99999:7:::
bin:*:19723:0:99999:7:::
sys:*:19723:0:99999:7:::
www-data:*:19723:0:99999:7:::
sshd:*:19723:0:99999:7:::
admin:$6$rounds=4096$SaLtVaLuE$LoNgHaShEdPaSsWoRdHeRe:19723:0:99999:7:::
ubuntu:$6$rounds=4096$RaNdOmSaLt$AnotherHashedPassword:19723:0:99999:7:::
deploy:$6$rounds=4096$DePlOySaLt$DeployUserPasswordHash:19723:0:99999:7:::
mysql:!:19723:0:99999:7:::
'''

    def _generate_group(self) -> str:
        """Generate realistic /etc/group content"""
        return '''root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,admin,ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
www-data:x:33:
backup:x:34:
sudo:x:27:admin,ubuntu
ssh:x:101:
admin:x:1000:
ubuntu:x:1001:
deploy:x:1003:
docker:x:999:admin,deploy
'''

    def _generate_sshd_config(self) -> str:
        """Generate realistic sshd_config"""
        return '''# OpenSSH Server Configuration
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Logging
SyslogFacility AUTH
LogLevel INFO

# Session
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Security
MaxAuthTries 6
MaxSessions 10
'''

    def _generate_nginx_conf(self) -> str:
        """Generate realistic nginx.conf"""
        return '''user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
'''

    def _generate_nginx_site(self, domain: str = 'default') -> str:
        """Generate nginx site configuration"""
        if domain == 'default':
            return '''server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.php;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
'''
        else:
            return f'''server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name {domain} www.{domain};
    root /var/www/{domain}/public_html;
    index index.php index.html;

    ssl_certificate /etc/ssl/certs/{domain}.crt;
    ssl_certificate_key /etc/ssl/private/{domain}.key;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}
}}
'''

    def _generate_wp_config(self) -> str:
        """Generate WordPress config file"""
        return '''<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'Wp_Pr0d_P@ssw0rd!' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'unique-phrase-here' );
define( 'SECURE_AUTH_KEY',  'unique-phrase-here' );
define( 'LOGGED_IN_KEY',    'unique-phrase-here' );
define( 'NONCE_KEY',        'unique-phrase-here' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
define( 'ABSPATH', __DIR__ . '/' );
require_once ABSPATH . 'wp-settings.php';
'''

    def _generate_env_file(self) -> str:
        """Generate Laravel/generic .env file"""
        return '''APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:kV9P8xM2dF3nL5jH7gT1bN4mQ6wE0rY8uI2oA5sD7fG=
APP_DEBUG=false
APP_URL=https://example.com

LOG_CHANNEL=stack
LOG_LEVEL=error

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app_user
DB_PASSWORD=Pr0ducT10n_DB_P@ss!

BROADCAST_DRIVER=log
CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=r3d1s_pr0d_p@ss
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@example.com
MAIL_PASSWORD=M@1lgun_API_K3y_H3r3

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=myapp-production
'''

    def _generate_php_config(self) -> str:
        """Generate PHP config file"""
        return '''<?php
return [
    'database' => [
        'host' => 'localhost',
        'name' => 'app_production',
        'user' => 'app_user',
        'pass' => 'Pr0ducT10n_DB_P@ss!',
    ],
    'redis' => [
        'host' => '127.0.0.1',
        'port' => 6379,
        'password' => 'r3d1s_pr0d_p@ss',
    ],
    'api_keys' => [
        'stripe' => 'sk_live_abc123def456',
        'sendgrid' => 'SG.xxxxxxxxxxxxx',
    ],
];
'''

    def _generate_bashrc(self) -> str:
        """Generate .bashrc file"""
        return '''# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s histappend
shopt -s checkwinsize

# Prompt
PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '

# Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
alias ..='cd ..'
alias ...='cd ../..'

# Enable programmable completion
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi

export PATH="$HOME/.local/bin:$PATH"
'''

    def _generate_bash_history(self) -> str:
        """Generate fake .bash_history"""
        return '''ls -la
cd /var/www
cat .env
sudo systemctl status nginx
mysql -u root -p
cd /home/admin/projects/webapp
git pull origin main
pip install -r requirements.txt
python manage.py migrate
sudo systemctl restart nginx
cat /var/log/nginx/error.log
df -h
free -m
htop
ps aux | grep python
netstat -tulpn
cd ~/scripts
./backup.sh
vim config.py
ssh deploy@192.168.1.100
scp backup.tar.gz root@backup-server:/backups/
history
'''

    def _generate_root_bash_history(self) -> str:
        """Generate root's .bash_history"""
        return '''apt update && apt upgrade -y
systemctl status sshd
cat /etc/passwd
cat /etc/shadow
useradd -m deploy
passwd deploy
usermod -aG sudo deploy
visudo
vim /etc/ssh/sshd_config
systemctl restart sshd
ufw allow 22
ufw allow 80
ufw allow 443
ufw enable
mysql -u root -p
mysqldump --all-databases > /root/backups/full_backup.sql
crontab -e
tail -f /var/log/auth.log
fail2ban-client status sshd
iptables -L -n
netstat -tulpn
lsof -i :3306
ps aux
kill -9 12345
docker ps
docker-compose up -d
certbot renew
history
'''

    def _generate_fake_private_key(self) -> str:
        """Generate fake SSH private key"""
        return '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AAAECxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END OPENSSH PRIVATE KEY-----
'''

    def _generate_fake_passwords(self) -> str:
        """Generate fake passwords.txt"""
        return '''# Server Credentials - CONFIDENTIAL
# Last updated: 2024-01-15

== Database ==
MySQL Root: R00t_MySQL_P@ss!
MySQL App User: app_user / Pr0ducT10n_DB_P@ss!
PostgreSQL: postgres / P0stgr3s_Adm1n!

== SSH ==
Root: Tr0ub4dor&3
Admin: @dmin_SSH_2024!
Deploy: D3pl0y_K3y_P@ss

== Web Services ==
WordPress Admin: admin / Wp_@dm1n_2024
phpMyAdmin: pma_admin / PhpMy@dmin!

== API Keys ==
Stripe Live: sk_live_abc123def456
SendGrid: SG.xxxxxxxxxxxxxxxxxxxx
AWS Access: AKIAIOSFODNN7EXAMPLE
AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCY

== Other ==
Router Admin: admin / admin123
VPN: vpnuser / V3ryS3cur3VPN!

NOTE: Change all passwords after reading!
'''

    def _generate_backup_script(self) -> str:
        """Generate backup.sh script"""
        return '''#!/bin/bash
# Automated backup script
# Runs daily via cron

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
MYSQL_USER="root"
MYSQL_PASS="R00t_MySQL_P@ss!"

# Backup MySQL
echo "Backing up MySQL databases..."
MYSQL_PWD="$MYSQL_PASS" mysqldump -u $MYSQL_USER --all-databases | gzip > $BACKUP_DIR/mysql_$DATE.sql.gz

# Backup web files
echo "Backing up web files..."
tar -czf $BACKUP_DIR/www_$DATE.tar.gz /var/www/

# Backup configs
echo "Backing up configs..."
tar -czf $BACKUP_DIR/etc_$DATE.tar.gz /etc/nginx /etc/mysql /etc/ssh

# Clean old backups (keep 7 days)
find $BACKUP_DIR -type f -mtime +7 -delete

echo "Backup completed: $DATE"
'''

    def _generate_deploy_script(self) -> str:
        """Generate deploy.sh script"""
        return '''#!/bin/bash
# Deployment script for production

set -e

APP_DIR="/var/www/example.com"
REPO="git@github.com:company/webapp.git"
BRANCH="main"

echo "Starting deployment..."

cd $APP_DIR

# Pull latest changes
git fetch origin
git checkout $BRANCH
git pull origin $BRANCH

# Install dependencies
composer install --no-dev --optimize-autoloader
npm install --production
npm run build

# Run migrations
php artisan migrate --force

# Clear caches
php artisan cache:clear
php artisan config:cache
php artisan route:cache

# Restart services
sudo systemctl reload php8.1-fpm
sudo systemctl reload nginx

echo "Deployment completed successfully!"
'''

    def _generate_syslog(self) -> str:
        """Generate syslog entries"""
        now = datetime.now()
        lines = []
        for i in range(20, 0, -1):
            t = now - timedelta(minutes=i*2)
            timestamp = t.strftime('%b %d %H:%M:%S')
            msgs = [
                f'{timestamp} {self.hostname} systemd[1]: Started Session 1 of user {self.username}.',
                f'{timestamp} {self.hostname} CRON[{random.randint(1000,9999)}]: (root) CMD (cd / && run-parts /etc/cron.hourly)',
                f'{timestamp} {self.hostname} kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.{random.randint(1,254)} DST=192.168.1.100',
                f'{timestamp} {self.hostname} nginx[{random.randint(1000,9999)}]: nginx: worker process {random.randint(1000,9999)} started',
                f'{timestamp} {self.hostname} mysql[{random.randint(1000,9999)}]: ready for connections. Version: 8.0.35',
            ]
            lines.append(random.choice(msgs))
        return '\n'.join(lines) + '\n'

    def _generate_nginx_access_log(self) -> str:
        """Generate nginx access.log entries"""
        now = datetime.now()
        lines = []
        paths = ['/', '/index.php', '/wp-admin/', '/api/v1/users', '/login', '/admin', '/robots.txt']
        for i in range(15, 0, -1):
            t = now - timedelta(minutes=i)
            timestamp = t.strftime('%d/%b/%Y:%H:%M:%S +0000')
            ip = f'{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
            path = random.choice(paths)
            status = random.choice([200, 200, 200, 301, 404, 500])
            lines.append(f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {random.randint(200,5000)} "-" "Mozilla/5.0"')
        return '\n'.join(lines) + '\n'

    def _generate_nginx_error_log(self) -> str:
        """Generate nginx error.log entries"""
        now = datetime.now()
        lines = []
        for i in range(5, 0, -1):
            t = now - timedelta(hours=i)
            timestamp = t.strftime('%Y/%m/%d %H:%M:%S')
            errors = [
                f'{timestamp} [error] 1234#1234: *5678 open() "/var/www/html/wp-admin" failed (2: No such file or directory)',
                f'{timestamp} [warn] 1234#1234: *5678 upstream response buffered',
                f'{timestamp} [error] 1234#1234: *5678 connect() failed (111: Connection refused) while connecting to upstream',
            ]
            lines.append(random.choice(errors))
        return '\n'.join(lines) + '\n'

    def get_prompt(self) -> str:
        """Get shell prompt with Ubuntu-style colors"""
        user_char = '#' if self.username == 'root' else '$'
        display_cwd = self.cwd.replace('/home/' + self.username, '~')
        if self.username == 'root':
            display_cwd = self.cwd.replace('/root', '~')

        # ANSI color codes (Ubuntu style)
        GREEN_BOLD = '\033[01;32m'  # Bold green for user@host
        BLUE_BOLD = '\033[01;34m'   # Bold blue for path
        RESET = '\033[00m'          # Reset colors

        # Root gets red instead of green
        if self.username == 'root':
            USER_COLOR = '\033[01;31m'  # Bold red for root
        else:
            USER_COLOR = GREEN_BOLD

        return f"{USER_COLOR}{self.username}@{self.hostname}{RESET}:{BLUE_BOLD}{display_cwd}{RESET}{user_char} "

    def _get_uptime_str(self) -> str:
        """Get realistic uptime string"""
        uptime = datetime.now() - self.boot_time
        days = uptime.days
        hours = uptime.seconds // 3600
        minutes = (uptime.seconds % 3600) // 60

        if days > 0:
            return f"{days} day{'s' if days > 1 else ''}, {hours:2d}:{minutes:02d}"
        else:
            return f"{hours:2d}:{minutes:02d}"

    def _resolve_path(self, path: str) -> str:
        """Resolve relative paths to absolute paths"""
        if not path:
            return self.cwd
        if path.startswith('~'):
            path = path.replace('~', self.env['HOME'], 1)
        if not path.startswith('/'):
            if self.cwd == '/':
                path = '/' + path
            else:
                path = self.cwd + '/' + path
        # Normalize path (handle .. and .)
        parts = []
        for part in path.split('/'):
            if part == '..':
                if parts:
                    parts.pop()
            elif part and part != '.':
                parts.append(part)
        return '/' + '/'.join(parts) if parts else '/'

    def execute(self, command: str) -> Tuple[str, bool]:
        """
        Execute a fake command with rule-based responses

        Returns:
            Tuple of (output, should_exit)
        """
        command = command.strip()
        if not command:
            return '', False

        # Store in history
        self.command_history.append(command)

        # Handle piped commands (simplified)
        if '|' in command:
            return self._handle_pipe(command)

        # Handle command chaining
        if '&&' in command:
            return self._handle_chain(command, '&&')
        if ';' in command:
            return self._handle_chain(command, ';')

        # Handle redirections (simplified - just acknowledge)
        if '>>' in command or '>' in command:
            return self._handle_redirect(command)

        # Parse command and args
        parts = self._parse_command(command)
        if not parts:
            return '', False

        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Handle sudo specially
        if cmd == 'sudo':
            return self._cmd_sudo(args)

        # Command handlers - comprehensive list
        handlers = {
            # Navigation & Files
            'ls': self._cmd_ls,
            'cd': self._cmd_cd,
            'pwd': self._cmd_pwd,
            'cat': self._cmd_cat,
            'head': self._cmd_head,
            'tail': self._cmd_tail,
            'less': self._cmd_cat,
            'more': self._cmd_cat,
            'touch': self._cmd_touch,
            'mkdir': self._cmd_mkdir,
            'rm': self._cmd_rm,
            'rmdir': self._cmd_rmdir,
            'cp': self._cmd_cp,
            'mv': self._cmd_mv,
            'ln': self._cmd_ln,
            'find': self._cmd_find,
            'locate': self._cmd_locate,
            'which': self._cmd_which,
            'file': self._cmd_file,
            'stat': self._cmd_stat,

            # User & Identity
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'groups': self._cmd_groups,
            'users': self._cmd_users,
            'who': self._cmd_who,
            'last': self._cmd_last,
            'passwd': self._cmd_passwd,

            # System Info
            'uname': self._cmd_uname,
            'hostname': self._cmd_hostname,
            'uptime': self._cmd_uptime,
            'w': self._cmd_w,
            'top': self._cmd_top,
            'free': self._cmd_free,
            'df': self._cmd_df,
            'du': self._cmd_du,
            'lscpu': self._cmd_lscpu,
            'lsblk': self._cmd_lsblk,
            'mount': self._cmd_mount,
            'dmesg': self._cmd_dmesg,
            'date': self._cmd_date,
            'cal': self._cmd_cal,

            # Process Management
            'ps': self._cmd_ps,
            'kill': self._cmd_kill,
            'pkill': self._cmd_pkill,
            'killall': self._cmd_killall,
            'nohup': self._cmd_nohup,
            'jobs': self._cmd_jobs,
            'bg': lambda a: ('', False),
            'fg': lambda a: ('', False),

            # Network
            'ifconfig': self._cmd_ifconfig,
            'ip': self._cmd_ip,
            'netstat': self._cmd_netstat,
            'ss': self._cmd_ss,
            'ping': self._cmd_ping,
            'traceroute': self._cmd_traceroute,
            'wget': self._cmd_wget,
            'curl': self._cmd_curl,
            'nc': self._cmd_nc,
            'netcat': self._cmd_nc,
            'ssh': self._cmd_ssh,
            'scp': self._cmd_scp,
            'ftp': self._cmd_ftp,
            'nslookup': self._cmd_nslookup,
            'dig': self._cmd_dig,
            'host': self._cmd_host,
            'arp': self._cmd_arp,

            # Permissions
            'chmod': self._cmd_chmod,
            'chown': self._cmd_chown,
            'chgrp': self._cmd_chgrp,
            'umask': self._cmd_umask,

            # Text Processing
            'echo': self._cmd_echo,
            'grep': self._cmd_grep,
            'awk': self._cmd_awk,
            'sed': self._cmd_sed,
            'cut': self._cmd_cut,
            'sort': self._cmd_sort,
            'uniq': self._cmd_uniq,
            'wc': self._cmd_wc,
            'tr': self._cmd_tr,
            'tee': self._cmd_tee,
            'xargs': self._cmd_xargs,

            # Archives
            'tar': self._cmd_tar,
            'gzip': self._cmd_gzip,
            'gunzip': self._cmd_gunzip,
            'zip': self._cmd_zip,
            'unzip': self._cmd_unzip,

            # Package Management
            'apt': self._cmd_apt,
            'apt-get': self._cmd_apt,
            'dpkg': self._cmd_dpkg,
            'yum': self._cmd_yum,
            'rpm': self._cmd_rpm,
            'pip': self._cmd_pip,
            'pip3': self._cmd_pip,
            'npm': self._cmd_npm,

            # Services
            'service': self._cmd_service,
            'systemctl': self._cmd_systemctl,

            # Cron
            'crontab': self._cmd_crontab,

            # Misc
            'env': self._cmd_env,
            'export': self._cmd_export,
            'set': self._cmd_set,
            'unset': lambda a: ('', False),
            'alias': self._cmd_alias,
            'type': self._cmd_type,
            'history': self._cmd_history,
            'clear': lambda a: ('\033[2J\033[H', False),
            'reset': lambda a: ('\033[2J\033[H', False),
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'logout': self._cmd_exit,
            'help': self._cmd_help,
            'man': self._cmd_man,

            # Programming
            'python': self._cmd_python,
            'python3': self._cmd_python,
            'php': self._cmd_php,
            'perl': self._cmd_perl,
            'ruby': self._cmd_ruby,
            'node': self._cmd_node,
            'bash': self._cmd_bash,
            'sh': self._cmd_bash,

            # Security
            'iptables': self._cmd_iptables,
            'nmap': self._cmd_nmap,
        }

        if cmd in handlers:
            return handlers[cmd](args)
        else:
            # Check if it's trying to run a script
            if cmd.startswith('./') or cmd.startswith('/'):
                return f"-bash: {cmd}: Permission denied\n", False
            return f"-bash: {cmd}: command not found\n", False

    def _parse_command(self, command: str) -> List[str]:
        """Parse command handling quotes"""
        parts = []
        current = ''
        in_quotes = None

        for char in command:
            if char in '"\'':
                if in_quotes == char:
                    in_quotes = None
                elif in_quotes is None:
                    in_quotes = char
                else:
                    current += char
            elif char == ' ' and in_quotes is None:
                if current:
                    parts.append(current)
                    current = ''
            else:
                current += char

        if current:
            parts.append(current)
        return parts

    def _handle_pipe(self, command: str) -> Tuple[str, bool]:
        """Handle piped commands"""
        cmds = [c.strip() for c in command.split('|')]
        # Execute first command
        output, should_exit = self.execute(cmds[0])
        # For pipes to grep, wc, etc. - simulate filtering
        for cmd in cmds[1:]:
            parts = cmd.split()
            if parts[0] == 'grep' and len(parts) > 1:
                pattern = parts[1]
                lines = output.split('\n')
                output = '\n'.join(l for l in lines if pattern in l)
            elif parts[0] == 'wc':
                lines = [l for l in output.split('\n') if l]
                if '-l' in parts:
                    output = f'{len(lines)}\n'
                else:
                    words = sum(len(l.split()) for l in lines)
                    chars = len(output)
                    output = f'{len(lines)} {words} {chars}\n'
            elif parts[0] == 'head':
                n = 10
                for i, p in enumerate(parts):
                    if p == '-n' and i + 1 < len(parts):
                        n = int(parts[i + 1])
                    elif p.startswith('-') and p[1:].isdigit():
                        n = int(p[1:])
                output = '\n'.join(output.split('\n')[:n]) + '\n'
            elif parts[0] == 'tail':
                n = 10
                for i, p in enumerate(parts):
                    if p == '-n' and i + 1 < len(parts):
                        n = int(parts[i + 1])
                    elif p.startswith('-') and p[1:].isdigit():
                        n = int(p[1:])
                output = '\n'.join(output.split('\n')[-n:]) + '\n'
        return output, should_exit

    def _handle_chain(self, command: str, sep: str) -> Tuple[str, bool]:
        """Handle command chaining with && or ;"""
        cmds = [c.strip() for c in command.split(sep)]
        output = ''
        for cmd in cmds:
            out, should_exit = self.execute(cmd)
            output += out
            if should_exit:
                return output, True
            # For &&, stop if command failed (simplified: continue always)
        return output, False

    def _handle_redirect(self, command: str) -> Tuple[str, bool]:
        """Handle output redirection"""
        if '>>' in command:
            parts = command.split('>>')
            cmd = parts[0].strip()
            # Just execute the command
            output, should_exit = self.execute(cmd)
            return '', should_exit
        elif '>' in command:
            parts = command.split('>')
            cmd = parts[0].strip()
            output, should_exit = self.execute(cmd)
            return '', should_exit
        return '', False

    # === FILE SYSTEM COMMANDS ===

    # ANSI color codes for ls output
    COLOR_DIR = '\033[01;34m'      # Bold blue for directories
    COLOR_EXEC = '\033[01;32m'     # Bold green for executables
    COLOR_LINK = '\033[01;36m'     # Bold cyan for symlinks
    COLOR_RESET = '\033[00m'       # Reset

    def _colorize_item(self, item: str, path: str) -> str:
        """Add color to ls item based on type"""
        full_path = f'{path}/{item}'.replace('//', '/')

        # Check if directory
        if full_path in self.filesystem or item in ('.', '..'):
            return f'{self.COLOR_DIR}{item}{self.COLOR_RESET}'

        # Check if executable (scripts, binaries)
        if item.endswith('.sh') or item.endswith('.py') or item in (
            'python3', 'node', 'php', 'java', 'gcc', 'make', 'git', 'vim',
            'nginx', 'apache2', 'mysqld', 'sshd', 'bash', 'sh'
        ):
            return f'{self.COLOR_EXEC}{item}{self.COLOR_RESET}'

        # Normal file - no color
        return item

    def _cmd_ls(self, args: List[str]) -> Tuple[str, bool]:
        """List directory contents with options support and colors"""
        show_all = '-a' in args or '-la' in args or '-al' in args or '-lah' in args
        long_format = '-l' in args or '-la' in args or '-al' in args or '-lah' in args

        # Get path (non-flag argument)
        path = self.cwd
        for arg in args:
            if not arg.startswith('-'):
                path = self._resolve_path(arg)
                break

        if path not in self.filesystem and path not in self.created_dirs:
            return f"ls: cannot access '{path}': No such file or directory\n", False

        items = list(self.filesystem.get(path, []))
        if show_all:
            items = ['.', '..'] + items

        if not items:
            return '', False

        if long_format:
            output = f'total {len(items) * 4}\n'
            for item in items:
                if item.startswith('.') and not show_all:
                    continue
                full_path = f'{path}/{item}'.replace('//', '/')
                is_dir = full_path in self.filesystem or item in ('.', '..')
                perms = 'drwxr-xr-x' if is_dir else '-rw-r--r--'
                size = random.randint(100, 10000) if not is_dir else 4096
                date = datetime.now().strftime('%b %d %H:%M')
                colored_item = self._colorize_item(item, path)
                output += f'{perms} 1 {self.username} {self.username} {size:8d} {date} {colored_item}\n'
            return output, False
        else:
            # Colorize each item
            colored_items = [self._colorize_item(item, path) for item in items]
            return '  '.join(colored_items) + '\n', False

    def _cmd_cd(self, args: List[str]) -> Tuple[str, bool]:
        """Change directory"""
        if not args or args[0] == '~':
            self.cwd = self.env['HOME']
            return '', False

        path = self._resolve_path(args[0])

        if path in self.filesystem:
            self.cwd = path
            return '', False
        elif path in self.created_dirs:
            self.cwd = path
            return '', False
        else:
            return f"-bash: cd: {args[0]}: No such file or directory\n", False

    def _cmd_pwd(self, args: List[str]) -> Tuple[str, bool]:
        return self.cwd + '\n', False

    def _cmd_cat(self, args: List[str]) -> Tuple[str, bool]:
        """Display file contents"""
        if not args:
            return '', False

        output = ''
        for arg in args:
            if arg.startswith('-'):
                continue
            path = self._resolve_path(arg)

            if path in self.file_contents:
                output += self.file_contents[path]
            elif path in self.created_files:
                output += self.created_files[path]
            else:
                return f"cat: {arg}: No such file or directory\n", False
        return output, False

    def _cmd_head(self, args: List[str]) -> Tuple[str, bool]:
        """Display first lines of file"""
        n = 10
        files = []
        i = 0
        while i < len(args):
            if args[i] == '-n' and i + 1 < len(args):
                n = int(args[i + 1])
                i += 2
            elif args[i].startswith('-') and args[i][1:].isdigit():
                n = int(args[i][1:])
                i += 1
            else:
                files.append(args[i])
                i += 1

        if not files:
            return '', False

        content, _ = self._cmd_cat(files)
        lines = content.split('\n')[:n]
        return '\n'.join(lines) + '\n', False

    def _cmd_tail(self, args: List[str]) -> Tuple[str, bool]:
        """Display last lines of file"""
        n = 10
        files = []
        i = 0
        while i < len(args):
            if args[i] == '-n' and i + 1 < len(args):
                n = int(args[i + 1])
                i += 2
            elif args[i].startswith('-') and args[i][1:].isdigit():
                n = int(args[i][1:])
                i += 1
            elif args[i] == '-f':
                i += 1  # Ignore follow mode
            else:
                files.append(args[i])
                i += 1

        if not files:
            return '', False

        content, _ = self._cmd_cat(files)
        lines = content.split('\n')[-n:]
        return '\n'.join(lines) + '\n', False

    def _cmd_touch(self, args: List[str]) -> Tuple[str, bool]:
        """Create empty file"""
        for arg in args:
            if not arg.startswith('-'):
                path = self._resolve_path(arg)
                self.created_files[path] = ''
        return '', False

    def _cmd_mkdir(self, args: List[str]) -> Tuple[str, bool]:
        """Create directory"""
        for arg in args:
            if not arg.startswith('-'):
                path = self._resolve_path(arg)
                self.created_dirs.add(path)
        return '', False

    def _cmd_rm(self, args: List[str]) -> Tuple[str, bool]:
        """Remove files"""
        for arg in args:
            if not arg.startswith('-'):
                path = self._resolve_path(arg)
                if path in self.created_files:
                    del self.created_files[path]
                elif path in self.file_contents:
                    return f"rm: cannot remove '{arg}': Permission denied\n", False
        return '', False

    def _cmd_rmdir(self, args: List[str]) -> Tuple[str, bool]:
        """Remove directory"""
        for arg in args:
            if not arg.startswith('-'):
                path = self._resolve_path(arg)
                if path in self.created_dirs:
                    self.created_dirs.remove(path)
                else:
                    return f"rmdir: failed to remove '{arg}': No such file or directory\n", False
        return '', False

    def _cmd_cp(self, args: List[str]) -> Tuple[str, bool]:
        """Copy files"""
        if len(args) < 2:
            return "cp: missing file operand\n", False
        return '', False  # Pretend it worked

    def _cmd_mv(self, args: List[str]) -> Tuple[str, bool]:
        """Move files"""
        if len(args) < 2:
            return "mv: missing file operand\n", False
        return '', False

    def _cmd_ln(self, args: List[str]) -> Tuple[str, bool]:
        """Create links"""
        if len(args) < 2:
            return "ln: missing file operand\n", False
        return '', False

    def _cmd_find(self, args: List[str]) -> Tuple[str, bool]:
        """Find files"""
        if not args:
            return '', False
        path = args[0] if not args[0].startswith('-') else '.'
        # Return some fake results
        return f'{path}\n{path}/file1\n{path}/file2\n', False

    def _cmd_locate(self, args: List[str]) -> Tuple[str, bool]:
        """Locate files in database"""
        if not args:
            return "locate: no pattern to search for specified\n", False
        return '', False  # No results

    def _cmd_which(self, args: List[str]) -> Tuple[str, bool]:
        """Show command path"""
        if not args:
            return '', False
        cmd = args[0]
        known = {'ls': '/bin/ls', 'cat': '/bin/cat', 'grep': '/bin/grep',
                 'python3': '/usr/bin/python3', 'bash': '/bin/bash', 'sh': '/bin/sh'}
        if cmd in known:
            return known[cmd] + '\n', False
        return f'{cmd} not found\n', False

    def _cmd_file(self, args: List[str]) -> Tuple[str, bool]:
        """Determine file type"""
        if not args:
            return "Usage: file [FILE...]\n", False
        path = self._resolve_path(args[0])
        if path in self.filesystem:
            return f"{args[0]}: directory\n", False
        elif path in self.file_contents or path in self.created_files:
            return f"{args[0]}: ASCII text\n", False
        return f"{args[0]}: cannot open (No such file or directory)\n", False

    def _cmd_stat(self, args: List[str]) -> Tuple[str, bool]:
        """Display file status"""
        if not args:
            return "stat: missing operand\n", False
        path = self._resolve_path(args[0])
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f'''  File: {args[0]}
  Size: 4096      \tBlocks: 8          IO Block: 4096   directory
Device: fd00h/64768d\tInode: 12345       Links: 2
Access: (0755/drwxr-xr-x)  Uid: ( 1000/ {self.username})   Gid: ( 1000/ {self.username})
Access: {now}.000000000 +0000
Modify: {now}.000000000 +0000
Change: {now}.000000000 +0000
''', False

    # === USER COMMANDS ===

    def _cmd_whoami(self, args: List[str]) -> Tuple[str, bool]:
        return self.username + '\n', False

    def _cmd_id(self, args: List[str]) -> Tuple[str, bool]:
        if self.username == 'root':
            return 'uid=0(root) gid=0(root) groups=0(root)\n', False
        return f'uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n', False

    def _cmd_groups(self, args: List[str]) -> Tuple[str, bool]:
        if self.username == 'root':
            return 'root\n', False
        return f'{self.username} sudo\n', False

    def _cmd_users(self, args: List[str]) -> Tuple[str, bool]:
        return f'{self.username}\n', False

    def _cmd_who(self, args: List[str]) -> Tuple[str, bool]:
        login_time = self.start_time.strftime('%Y-%m-%d %H:%M')
        return f'{self.username}  pts/0        {login_time} (10.0.0.1)\n', False

    def _cmd_last(self, args: List[str]) -> Tuple[str, bool]:
        now = datetime.now()
        lines = []
        for i in range(5):
            t = now - timedelta(hours=i * 24 + random.randint(1, 12))
            lines.append(f'{self.username:<8} pts/0        10.0.0.{random.randint(1,254):<3}  ' +
                        f'{t.strftime("%a %b %d %H:%M")}   still logged in')
        lines.append('')
        lines.append('wtmp begins ' + (now - timedelta(days=30)).strftime('%a %b %d %H:%M:%S %Y'))
        return '\n'.join(lines) + '\n', False

    def _cmd_passwd(self, args: List[str]) -> Tuple[str, bool]:
        return 'Changing password for ' + self.username + '.\nCurrent password: ', False

    # === SYSTEM INFO COMMANDS ===

    def _cmd_uname(self, args: List[str]) -> Tuple[str, bool]:
        if '-a' in args:
            return f'Linux {self.hostname} {self.profile["kernel"]} #1 SMP PREEMPT_DYNAMIC ' + \
                   f'{self.profile["arch"]} GNU/Linux\n', False
        elif '-r' in args:
            return self.profile["kernel"] + '\n', False
        elif '-n' in args:
            return self.hostname + '\n', False
        elif '-m' in args:
            return self.profile["arch"] + '\n', False
        return 'Linux\n', False

    def _cmd_hostname(self, args: List[str]) -> Tuple[str, bool]:
        return self.hostname + '\n', False

    def _cmd_uptime(self, args: List[str]) -> Tuple[str, bool]:
        now = datetime.now().strftime('%H:%M:%S')
        uptime_str = self._get_uptime_str()
        load = f"{random.uniform(0, 0.5):.2f}, {random.uniform(0, 0.3):.2f}, {random.uniform(0, 0.2):.2f}"
        return f' {now} up {uptime_str},  1 user,  load average: {load}\n', False

    def _cmd_w(self, args: List[str]) -> Tuple[str, bool]:
        now = datetime.now().strftime('%H:%M:%S')
        uptime_str = self._get_uptime_str()
        load = f"{random.uniform(0, 0.5):.2f}, {random.uniform(0, 0.3):.2f}, {random.uniform(0, 0.2):.2f}"
        login_time = self.start_time.strftime('%H:%M')
        return f''' {now} up {uptime_str},  1 user,  load average: {load}
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{self.username:<8} pts/0    10.0.0.1         {login_time}    0.00s  0.05s  0.00s w
''', False

    def _cmd_top(self, args: List[str]) -> Tuple[str, bool]:
        """Display processes - single snapshot"""
        now = datetime.now().strftime('%H:%M:%S')
        uptime_str = self._get_uptime_str()
        mem_total = random.randint(4, 16) * 1024
        mem_used = random.randint(int(mem_total * 0.3), int(mem_total * 0.7))
        return f'''top - {now} up {uptime_str},  1 user,  load average: 0.00, 0.01, 0.05
Tasks:  95 total,   1 running,  94 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :  {mem_total:.1f} total,   {mem_total - mem_used:.1f} free,   {mem_used:.1f} used,    512.0 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,     0.0 used.   {mem_total - mem_used + 400:.1f} avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0  168256  13024   8432 S   0.0   0.1   0:01.52 systemd
  {random.randint(100,999)} root      20   0   25104   6784   5440 S   0.0   0.0   0:00.05 sshd
  {random.randint(1000,9999)} {self.username:<8}  20   0   10072   3384   2880 S   0.0   0.0   0:00.01 bash
''', False

    def _cmd_free(self, args: List[str]) -> Tuple[str, bool]:
        """Display memory usage"""
        total = random.randint(4, 16) * 1024 * 1024
        used = random.randint(int(total * 0.3), int(total * 0.6))
        free = total - used
        shared = random.randint(10000, 100000)
        buff = random.randint(500000, 2000000)
        available = free + buff

        if '-h' in args:
            return f'''              total        used        free      shared  buff/cache   available
Mem:          {total // 1024 // 1024}Gi       {used // 1024 // 1024}Gi       {free // 1024 // 1024}Gi       {shared // 1024}Mi       {buff // 1024 // 1024}Gi       {available // 1024 // 1024}Gi
Swap:         2.0Gi          0B       2.0Gi
''', False

        return f'''              total        used        free      shared  buff/cache   available
Mem:       {total}    {used}    {free}    {shared}    {buff}    {available}
Swap:      2097148           0     2097148
''', False

    def _cmd_df(self, args: List[str]) -> Tuple[str, bool]:
        """Display disk space"""
        if '-h' in args:
            return '''Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   12G   36G  25% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda2       100G   45G   50G  48% /home
''', False
        return '''Filesystem     1K-blocks     Used Available Use% Mounted on
/dev/sda1       52428800 12582912  37748736  25% /
tmpfs            2097152        0   2097152   0% /dev/shm
/dev/sda2      104857600 47185920  52428800  48% /home
''', False

    def _cmd_du(self, args: List[str]) -> Tuple[str, bool]:
        """Display disk usage"""
        path = args[-1] if args and not args[-1].startswith('-') else '.'
        return f'{random.randint(1000, 50000)}\t{path}\n', False

    def _cmd_lscpu(self, args: List[str]) -> Tuple[str, bool]:
        return '''Architecture:            x86_64
CPU op-mode(s):          32-bit, 64-bit
Byte Order:              Little Endian
CPU(s):                  4
On-line CPU(s) list:     0-3
Thread(s) per core:      2
Core(s) per socket:      2
Socket(s):               1
NUMA node(s):            1
Vendor ID:               GenuineIntel
CPU family:              6
Model:                   85
Model name:              Intel(R) Xeon(R) CPU @ 2.20GHz
Stepping:                7
CPU MHz:                 2199.998
''', False

    def _cmd_lsblk(self, args: List[str]) -> Tuple[str, bool]:
        return '''NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
sda      8:0    0   100G  0 disk
├─sda1   8:1    0    50G  0 part /
└─sda2   8:2    0    50G  0 part /home
''', False

    def _cmd_mount(self, args: List[str]) -> Tuple[str, bool]:
        return '''/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
/dev/sda2 on /home type ext4 (rw,relatime)
tmpfs on /run type tmpfs (rw,nosuid,nodev,mode=755)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
''', False

    def _cmd_dmesg(self, args: List[str]) -> Tuple[str, bool]:
        return '''[    0.000000] Linux version 5.15.0-91-generic
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-91-generic root=/dev/sda1
[    0.000000] BIOS-provided physical RAM map:
[    0.100000] Initializing cgroup subsys cpuset
[    1.000000] smpboot: CPU0: Intel(R) Xeon(R) CPU @ 2.20GHz
[    2.000000] NET: Registered protocol family 2
[    3.000000] EXT4-fs (sda1): mounted filesystem with ordered data mode
''', False

    def _cmd_date(self, args: List[str]) -> Tuple[str, bool]:
        return datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y') + '\n', False

    def _cmd_cal(self, args: List[str]) -> Tuple[str, bool]:
        now = datetime.now()
        return f'''    {now.strftime("%B %Y")}
Su Mo Tu We Th Fr Sa
             1  2  3
 4  5  6  7  8  9 10
11 12 13 14 15 16 17
18 19 20 21 22 23 24
25 26 27 28 29 30 31
''', False

    # === PROCESS COMMANDS ===

    def _cmd_ps(self, args: List[str]) -> Tuple[str, bool]:
        if 'aux' in ' '.join(args) or '-ef' in args or '-e' in args:
            return f'''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168256 13024 ?        Ss   Jan01   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]
root       {random.randint(100, 500)}  0.0  0.0  25104  6784 ?        Ss   10:00   0:00 sshd: {self.username} [priv]
{self.username:<8} {random.randint(1000, 2000)}  0.0  0.0  25240  5120 ?        S    10:00   0:00 sshd: {self.username}@pts/0
{self.username:<8} {random.randint(2000, 3000)}  0.0  0.0  10072  3384 pts/0    Ss   10:00   0:00 -bash
{self.username:<8} {random.randint(3000, 4000)}  0.0  0.0  11240  2280 pts/0    R+   {datetime.now().strftime("%H:%M")}   0:00 ps aux
''', False
        return f'''  PID TTY          TIME CMD
 {random.randint(1000, 2000)} pts/0    00:00:00 bash
 {random.randint(2000, 3000)} pts/0    00:00:00 ps
''', False

    def _cmd_kill(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n", False
        return '', False

    def _cmd_pkill(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_killall(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "killall: usage: killall [options] name ...\n", False
        return '', False

    def _cmd_nohup(self, args: List[str]) -> Tuple[str, bool]:
        if args:
            return 'nohup: appending output to nohup.out\n', False
        return "nohup: missing operand\n", False

    def _cmd_jobs(self, args: List[str]) -> Tuple[str, bool]:
        return '', False  # No background jobs

    # === NETWORK COMMANDS ===

    def _cmd_ifconfig(self, args: List[str]) -> Tuple[str, bool]:
        return '''eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe8e:8aa8  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:8e:8a:a8  txqueuelen 1000  (Ethernet)
        RX packets 154623  bytes 162789345 (162.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 87234  bytes 12456789 (12.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1234  bytes 123456 (123.4 KB)
        TX packets 1234  bytes 123456 (123.4 KB)
''', False

    def _cmd_ip(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n', False

        if args[0] in ('addr', 'a'):
            return '''1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:8e:8a:a8 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86399sec preferred_lft 86399sec
''', False
        elif args[0] in ('route', 'r'):
            return '''default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100
''', False
        elif args[0] == 'link':
            return '''1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:8e:8a:a8 brd ff:ff:ff:ff:ff:ff
''', False
        return 'Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n', False

    def _cmd_netstat(self, args: List[str]) -> Tuple[str, bool]:
        if '-tulpn' in ''.join(args) or '-an' in ''.join(args):
            return '''Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      5678/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      9012/mysqld
tcp        0      0 192.168.1.100:22        10.0.0.1:54321          ESTABLISHED 2345/sshd
''', False
        return '''Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 192.168.1.100:22        10.0.0.1:54321          ESTABLISHED
''', False

    def _cmd_ss(self, args: List[str]) -> Tuple[str, bool]:
        return '''Netid State  Recv-Q Send-Q   Local Address:Port   Peer Address:Port
tcp   LISTEN 0      128            0.0.0.0:22          0.0.0.0:*
tcp   LISTEN 0      128            0.0.0.0:80          0.0.0.0:*
tcp   ESTAB  0      0      192.168.1.100:22       10.0.0.1:54321
''', False

    def _cmd_ping(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'ping: usage error: Destination address required\n', False
        host = args[-1]
        return f'''PING {host} (93.184.216.34) 56(84) bytes of data.
64 bytes from {host} (93.184.216.34): icmp_seq=1 ttl=56 time=12.3 ms
64 bytes from {host} (93.184.216.34): icmp_seq=2 ttl=56 time=11.8 ms
64 bytes from {host} (93.184.216.34): icmp_seq=3 ttl=56 time=12.1 ms
^C
--- {host} ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.800/12.066/12.300/0.205 ms
''', False

    def _cmd_traceroute(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'Usage: traceroute host\n', False
        return f'''traceroute to {args[-1]} (93.184.216.34), 30 hops max, 60 byte packets
 1  gateway (192.168.1.1)  1.234 ms  1.123 ms  1.089 ms
 2  10.0.0.1 (10.0.0.1)  5.432 ms  5.321 ms  5.234 ms
 3  * * *
 4  {args[-1]} (93.184.216.34)  12.345 ms  12.234 ms  12.123 ms
''', False

    def _cmd_wget(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'wget: missing URL\nUsage: wget [OPTION]... [URL]...\n', False

        url = args[-1]
        if not url.startswith('http'):
            url = 'http://' + url

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f'''--{now}--  {url}
Resolving {url.split('/')[2]}... failed: Temporary failure in name resolution.
wget: unable to resolve host address '{url.split('/')[2]}'
''', False

    def _cmd_curl(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "curl: try 'curl --help' or 'curl --manual' for more information\n", False

        url = None
        for arg in args:
            if not arg.startswith('-') and ('.' in arg or arg.startswith('http')):
                url = arg
                break

        if url:
            host = url.replace('http://', '').replace('https://', '').split('/')[0]
            return f"curl: (6) Could not resolve host: {host}\n", False
        return "curl: no URL specified!\n", False

    def _cmd_nc(self, args: List[str]) -> Tuple[str, bool]:
        """Netcat - commonly used for reverse shells"""
        if '-l' in args or '-e' in args:
            return '', False  # Silent for listener mode
        if len(args) >= 2:
            return f"nc: connect to {args[-2]} port {args[-1]} (tcp) failed: Connection refused\n", False
        return 'usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-O length] ...\n', False

    def _cmd_ssh(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] ...\n', False
        return f'ssh: connect to host {args[-1]} port 22: Connection refused\n', False

    def _cmd_scp(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return 'usage: scp [-346BCpqrTv] [-c cipher] [-F ssh_config] ...\n', False
        return 'scp: Connection refused\n', False

    def _cmd_ftp(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'usage: ftp host [port]\n', False
        return f'ftp: connect: Connection refused\n', False

    def _cmd_nslookup(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return '> ', False
        return f'''Server:\t\t8.8.8.8
Address:\t8.8.8.8#53

Non-authoritative answer:
Name:\t{args[0]}
Address: 93.184.216.34
''', False

    def _cmd_dig(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return '; <<>> DiG 9.16.1-Ubuntu <<>>\n;; connection timed out\n', False
        return f'''; <<>> DiG 9.16.1-Ubuntu <<>> {args[0]}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
{args[0]}.\t\t300\tIN\tA\t93.184.216.34

;; Query time: 23 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: {datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")}
''', False

    def _cmd_host(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'Usage: host name [server]\n', False
        return f'{args[0]} has address 93.184.216.34\n', False

    def _cmd_arp(self, args: List[str]) -> Tuple[str, bool]:
        return '''Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   00:11:22:33:44:55   C                     eth0
192.168.1.254            ether   aa:bb:cc:dd:ee:ff   C                     eth0
''', False

    # === PERMISSION COMMANDS ===

    def _cmd_chmod(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return "chmod: missing operand\n", False
        return '', False

    def _cmd_chown(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return "chown: missing operand\n", False
        if self.username != 'root':
            return f"chown: changing ownership of '{args[-1]}': Operation not permitted\n", False
        return '', False

    def _cmd_chgrp(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return "chgrp: missing operand\n", False
        return '', False

    def _cmd_umask(self, args: List[str]) -> Tuple[str, bool]:
        return '0022\n', False

    # === TEXT PROCESSING ===

    def _cmd_echo(self, args: List[str]) -> Tuple[str, bool]:
        text = ' '.join(args)
        # Handle variable expansion
        for var, val in self.env.items():
            text = text.replace(f'${var}', val)
            text = text.replace(f'${{{var}}}', val)
        return text + '\n', False

    def _cmd_grep(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "Usage: grep [OPTION]... PATTERN [FILE]...\n", False
        return '', False

    def _cmd_awk(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_sed(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_cut(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_sort(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_uniq(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_wc(self, args: List[str]) -> Tuple[str, bool]:
        if not args or args[0].startswith('-'):
            return "0 0 0\n", False
        content, _ = self._cmd_cat([a for a in args if not a.startswith('-')])
        lines = len(content.split('\n'))
        words = len(content.split())
        chars = len(content)
        if '-l' in args:
            return f'{lines}\n', False
        if '-w' in args:
            return f'{words}\n', False
        if '-c' in args:
            return f'{chars}\n', False
        return f'{lines} {words} {chars}\n', False

    def _cmd_tr(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_tee(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_xargs(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    # === ARCHIVE COMMANDS ===

    def _cmd_tar(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\n", False
        if 'x' in args[0]:
            return '', False  # Extract silently
        if 'c' in args[0]:
            return '', False  # Create silently
        if 't' in args[0]:
            return 'file1.txt\nfile2.txt\ndir/\n', False
        return '', False

    def _cmd_gzip(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_gunzip(self, args: List[str]) -> Tuple[str, bool]:
        return '', False

    def _cmd_zip(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return "zip error: Nothing to do!\n", False
        return f"  adding: {args[-1]} (stored 0%)\n", False

    def _cmd_unzip(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "UnZip 6.00 of 20 April 2009, by Debian.\nUsage: unzip file.zip\n", False
        return f"Archive:  {args[-1]}\n   creating: extracted/\n", False

    # === PACKAGE MANAGEMENT ===

    def _cmd_apt(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "apt 2.4.11 (amd64)\nUsage: apt [options] command\n", False
        if self.username != 'root' and not self.sudo_authenticated:
            return "E: Could not open lock file - open (13: Permission denied)\n", False
        if args[0] == 'update':
            return '''Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]
Reading package lists... Done
''', False
        if args[0] == 'install':
            return "Reading package lists... Done\nBuilding dependency tree... Done\nPackage not found.\n", False
        return '', False

    def _cmd_dpkg(self, args: List[str]) -> Tuple[str, bool]:
        if '-l' in args:
            return '''Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version      Architecture Description
+++-==============-============-============-========================================
ii  bash           5.1-6ubuntu1 amd64        GNU Bourne Again SHell
ii  coreutils      8.32-4.1ubun amd64        GNU core utilities
ii  openssh-server 1:8.9p1-3ubu amd64        secure shell (SSH) server
''', False
        return '', False

    def _cmd_yum(self, args: List[str]) -> Tuple[str, bool]:
        return "yum: command not found (This is a Debian-based system. Use apt instead.)\n", False

    def _cmd_rpm(self, args: List[str]) -> Tuple[str, bool]:
        return "rpm: command not found (This is a Debian-based system. Use dpkg instead.)\n", False

    def _cmd_pip(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return '''Usage:
  pip3 <command> [options]

Commands:
  install     Install packages.
  list        List installed packages.
''', False
        if args[0] == 'list':
            return '''Package         Version
--------------- -------
pip             22.0.2
setuptools      59.6.0
wheel           0.37.1
''', False
        return 'Requirement already satisfied\n', False

    def _cmd_npm(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return 'Usage: npm <command>\n', False
        return 'npm WARN old lockfile\n', False

    # === SERVICE COMMANDS ===

    def _cmd_service(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return "Usage: service <service> <action>\n", False
        if self.username != 'root' and not self.sudo_authenticated:
            return f"service: unable to connect to system bus: Permission denied\n", False
        return '', False

    def _cmd_systemctl(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "systemctl: missing command\n", False
        if self.username != 'root' and not self.sudo_authenticated:
            return "Failed to connect to bus: Permission denied\n", False
        if args[0] == 'status':
            svc = args[1] if len(args) > 1 else 'sshd'
            return f'''* {svc}.service - OpenSSH Daemon
     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled)
     Active: active (running) since Mon 2024-01-01 00:00:00 UTC; 1 day ago
   Main PID: 1234 ({svc})
      Tasks: 1 (limit: 4915)
     Memory: 5.2M
        CPU: 123ms
     CGroup: /system.slice/{svc}.service
             `-1234 /usr/sbin/{svc} -D
''', False
        if args[0] in ('start', 'stop', 'restart', 'enable', 'disable'):
            return '', False
        if args[0] == 'list-units':
            return '''UNIT                       LOAD   ACTIVE SUB     DESCRIPTION
sshd.service               loaded active running OpenSSH Daemon
nginx.service              loaded active running nginx HTTP Server
mysql.service              loaded active running MySQL Database Server
cron.service               loaded active running Regular background program processing
''', False
        return '', False

    def _cmd_crontab(self, args: List[str]) -> Tuple[str, bool]:
        if '-l' in args:
            return 'no crontab for ' + self.username + '\n', False
        if '-e' in args:
            return 'crontab: installing new crontab\n', False
        return '', False

    # === MISC COMMANDS ===

    def _cmd_env(self, args: List[str]) -> Tuple[str, bool]:
        output = ''
        for key, val in self.env.items():
            output += f'{key}={val}\n'
        return output, False

    def _cmd_export(self, args: List[str]) -> Tuple[str, bool]:
        for arg in args:
            if '=' in arg:
                key, val = arg.split('=', 1)
                self.env[key] = val
        return '', False

    def _cmd_set(self, args: List[str]) -> Tuple[str, bool]:
        return self._cmd_env(args)

    def _cmd_alias(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return '''alias ls='ls --color=auto'
alias ll='ls -la'
alias grep='grep --color=auto'
''', False
        return '', False

    def _cmd_type(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return '', False
        cmd = args[0]
        builtins = ['cd', 'exit', 'export', 'alias', 'echo', 'pwd']
        if cmd in builtins:
            return f'{cmd} is a shell builtin\n', False
        return f'{cmd} is /usr/bin/{cmd}\n', False

    def _cmd_history(self, args: List[str]) -> Tuple[str, bool]:
        output = ''
        for i, cmd in enumerate(self.command_history[-50:], 1):
            output += f'  {i:3d}  {cmd}\n'
        return output if output else '    1  history\n', False

    def _cmd_exit(self, args: List[str]) -> Tuple[str, bool]:
        return 'logout\n', True

    def _cmd_help(self, args: List[str]) -> Tuple[str, bool]:
        return '''GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally. Type 'help' to see this list.

 cd [dir]         Change the shell working directory.
 echo [arg ...]   Write arguments to standard output.
 exit [n]         Exit the shell.
 export [name]    Set export attribute for shell variables.
 history          Display the command history list.
 pwd              Print the current working directory.
 type name        Describe a command.

For more information, use 'man bash'.
''', False

    def _cmd_man(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "What manual page do you want?\n", False
        return f"No manual entry for {args[0]}\n", False

    # === PROGRAMMING LANGUAGES ===

    def _cmd_python(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "Python 3.10.12 (main, Jun 11 2023, 05:26:28) [GCC 11.4.0] on linux\n>>> ", False
        if args[0] == '--version' or args[0] == '-V':
            return "Python 3.10.12\n", False
        if args[0] == '-c' and len(args) > 1:
            return '', False  # Pretend to execute
        return f"python: can't open file '{args[0]}': [Errno 2] No such file or directory\n", False

    def _cmd_php(self, args: List[str]) -> Tuple[str, bool]:
        if '--version' in args or '-v' in args:
            return "PHP 8.1.2-1ubuntu2.14 (cli) (built: Aug  1 2023 10:29:38) (NTS)\n", False
        return "Could not open input file\n", False

    def _cmd_perl(self, args: List[str]) -> Tuple[str, bool]:
        if '-v' in args:
            return "This is perl 5, version 34, subversion 0 (v5.34.0)\n", False
        return '', False

    def _cmd_ruby(self, args: List[str]) -> Tuple[str, bool]:
        if '-v' in args:
            return "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233) [x86_64-linux-gnu]\n", False
        return '', False

    def _cmd_node(self, args: List[str]) -> Tuple[str, bool]:
        if '-v' in args or '--version' in args:
            return "v18.17.1\n", False
        return "> ", False

    def _cmd_bash(self, args: List[str]) -> Tuple[str, bool]:
        if '-c' in args and len(args) > args.index('-c') + 1:
            cmd_idx = args.index('-c') + 1
            return self.execute(args[cmd_idx])
        return '', False

    # === SECURITY COMMANDS ===

    def _cmd_iptables(self, args: List[str]) -> Tuple[str, bool]:
        if self.username != 'root' and not self.sudo_authenticated:
            return "iptables: Permission denied (you must be root).\n", False
        if '-L' in args:
            return '''Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
''', False
        return '', False

    def _cmd_nmap(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return "Nmap 7.80 ( https://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}\n", False
        return f'''Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for {args[-1]}
Host is up (0.00043s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open https

Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
''', False

    # === SUDO ===

    def _cmd_sudo(self, args: List[str]) -> Tuple[str, bool]:
        """Handle sudo command with password prompt"""
        if not args:
            return "usage: sudo -h | -K | -k | -V\n", False

        # Skip flags
        cmd_args = []
        skip_next = False
        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if arg in ('-u', '-g'):
                skip_next = True
                continue
            if arg.startswith('-'):
                continue
            cmd_args = args[i:]
            break

        if not cmd_args:
            return '', False

        # Simulate authentication
        self.sudo_authenticated = True

        # Execute the command as if root
        old_username = self.username
        self.username = 'root'
        result = self.execute(' '.join(cmd_args))
        self.username = old_username

        return result


class SSHServerInterface(paramiko.ServerInterface):
    """Paramiko SSH Server Interface"""

    def __init__(self, client_ip: str, on_auth: Callable = None):
        self.client_ip = client_ip
        self.on_auth = on_auth
        self.username = None
        self.authenticated = False

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Handle password authentication - always allow for honeypot"""
        self.username = username

        # Log authentication attempt
        print(f"[SSH] Auth attempt from {self.client_ip}: {username}:{password}")

        if self.on_auth:
            self.on_auth(
                ip_address=self.client_ip,
                username=username,
                password=password
            )

        # Accept all credentials for honeypot
        self.authenticated = True
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Reject public key auth to force password"""
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return 'password'

    def check_channel_shell_request(self, channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        return True


class SSHHoneypot:
    """SSH Honeypot Server"""

    def __init__(self,
                 host: str = '0.0.0.0',
                 port: int = 2222,
                 host_key_path: str = None,
                 on_attack: Callable = None):
        """
        Initialize SSH Honeypot

        Args:
            host: Host to bind to
            port: Port to listen on
            host_key_path: Path to SSH host key file
            on_attack: Callback function for attack events
        """
        self.host = host
        self.port = port
        self.on_attack = on_attack
        self._running = False
        self._server_socket = None
        self._thread = None
        self._sessions: Dict[str, dict] = {}

        # Load or generate host key
        self.host_key = self._load_host_key(host_key_path)

    def _load_host_key(self, key_path: str = None) -> RSAKey:
        """Load or generate SSH host key"""
        if key_path is None:
            key_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'data', 'ssh_host_key'
            )

        if os.path.exists(key_path):
            try:
                return RSAKey.from_private_key_file(key_path)
            except Exception as e:
                print(f"[SSH] Warning: Could not load host key: {e}")

        # Generate new key
        print("[SSH] Generating new host key...")
        key = RSAKey.generate(2048)

        # Save key
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        key.write_private_key_file(key_path)

        return key

    def _handle_auth(self, ip_address: str, username: str, password: str) -> None:
        """Handle authentication attempt"""
        if self.on_attack:
            self.on_attack(
                source='SSH',
                ip_address=ip_address,
                username=username,
                password=password,
                extra_data={'type': 'auth'}
            )

    def _handle_command(self, ip_address: str, command: str, session_id: str) -> None:
        """Handle command execution with rule-based classification"""
        # Classify the command using rule-based patterns
        threat_categories = classify_command(command)

        if self.on_attack:
            self.on_attack(
                source='SSH',
                ip_address=ip_address,
                command=command,
                session_id=session_id,
                extra_data={
                    'type': 'command',
                    'threat_categories': threat_categories,
                    'is_suspicious': len(threat_categories) > 0,
                }
            )

        if threat_categories:
            print(f"[SSH] Suspicious command from {ip_address}: {command} -> {threat_categories}")

    def _handle_client(self, client_socket: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Handle incoming SSH client connection"""
        client_ip = client_addr[0]
        session_id = str(uuid.uuid4())[:8]

        print(f"[SSH] Connection from {client_ip} (session: {session_id})")

        try:
            # Create transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1"

            # Create server interface
            server = SSHServerInterface(
                client_ip=client_ip,
                on_auth=lambda **kw: self._handle_auth(**kw)
            )

            # Start SSH server
            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                print(f"[SSH] SSH negotiation failed: {e}")
                return

            # Wait for authentication
            channel = transport.accept(timeout=30)
            if channel is None:
                print(f"[SSH] No channel from {client_ip}")
                return

            if not server.authenticated:
                print(f"[SSH] Authentication failed from {client_ip}")
                return

            # Store session
            self._sessions[session_id] = {
                'ip': client_ip,
                'username': server.username,
                'start_time': datetime.now(),
                'commands': []
            }

            # Create fake shell
            shell = FakeShell(server.username)

            # Send realistic welcome banner
            last_login = (datetime.now() - timedelta(hours=random.randint(1, 48))).strftime('%a %b %d %H:%M:%S %Y')
            welcome_banner = f'''Welcome to {shell.profile["os_name"]}

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")}

  System load:  {random.uniform(0, 0.5):.2f}              Processes:             {random.randint(90, 150)}
  Usage of /:   {random.randint(15, 45)}% of 49.15GB     Users logged in:       1
  Memory usage: {random.randint(20, 60)}%               IPv4 address for eth0: 192.168.1.100
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, entity K8s clusters: https://ubuntu.com/blog/microk8s

{random.randint(0, 5)} updates can be applied immediately.
{random.randint(0, 2)} of these updates are standard security updates.

Last login: {last_login} from 10.0.0.{random.randint(1, 254)}
'''
            channel.send(welcome_banner.replace('\n', '\r\n'))
            channel.send(shell.get_prompt())

            # Command buffer
            command_buffer = ""

            while transport.is_active():
                try:
                    data = channel.recv(1024)
                    if not data:
                        break

                    for char in data.decode('utf-8', errors='ignore'):
                        if char == '\r' or char == '\n':
                            # Echo newline first (like real terminal)
                            channel.send('\r\n')

                            if command_buffer.strip():
                                # Log command
                                self._sessions[session_id]['commands'].append(command_buffer)
                                self._handle_command(client_ip, command_buffer, session_id)

                                # Execute command
                                output, should_exit = shell.execute(command_buffer)

                                if output:
                                    # Ensure output ends with newline
                                    if not output.endswith('\n'):
                                        output += '\n'
                                    # Convert \n to \r\n for terminal
                                    formatted_output = output.replace('\n', '\r\n')
                                    channel.send(formatted_output)

                                if should_exit:
                                    channel.close()
                                    break

                            command_buffer = ""
                            # Send prompt on new line
                            channel.send(shell.get_prompt())

                        elif char == '\x7f' or char == '\x08':  # Backspace
                            if command_buffer:
                                command_buffer = command_buffer[:-1]
                                channel.send('\b \b')

                        elif char == '\x03':  # Ctrl+C
                            command_buffer = ""
                            channel.send('^C\r\n' + shell.get_prompt())

                        elif char == '\x04':  # Ctrl+D
                            channel.send('logout\r\n')
                            channel.close()
                            break

                        elif ord(char) >= 32:  # Printable characters
                            command_buffer += char
                            channel.send(char)

                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[SSH] Error handling input from {client_ip}: {e}")
                    break

        except Exception as e:
            print(f"[SSH] Error handling client {client_ip}: {e}")

        finally:
            # Cleanup
            if session_id in self._sessions:
                session = self._sessions.pop(session_id)
                print(f"[SSH] Session {session_id} ended. Commands: {len(session['commands'])}")

            try:
                transport.close()
            except:
                pass

            try:
                client_socket.close()
            except:
                pass

    def start(self, threaded: bool = True) -> None:
        """Start the SSH honeypot server"""
        self._running = True

        # Create server socket
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(100)
            print(f"[SSH] Honeypot started on {self.host}:{self.port}")
        except PermissionError:
            print(f"[SSH] Error: Permission denied for port {self.port}. Try running as root or use port > 1024")
            return
        except Exception as e:
            print(f"[SSH] Error starting server: {e}")
            return

        if threaded:
            self._thread = threading.Thread(target=self._accept_connections, daemon=True)
            self._thread.start()
        else:
            self._accept_connections()

    def _accept_connections(self) -> None:
        """Accept incoming connections"""
        while self._running:
            try:
                self._server_socket.settimeout(1.0)
                try:
                    client_socket, client_addr = self._server_socket.accept()
                    client_socket.settimeout(60)

                    # Handle client in new thread
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    thread.start()

                except socket.timeout:
                    continue

            except Exception as e:
                if self._running:
                    print(f"[SSH] Error accepting connection: {e}")

    def stop(self) -> None:
        """Stop the SSH honeypot server"""
        self._running = False

        if self._server_socket:
            try:
                self._server_socket.close()
            except:
                pass

        print("[SSH] Honeypot stopped")


if __name__ == '__main__':
    # Test run
    def test_callback(**kwargs):
        print(f"Attack detected: {kwargs}")

    honeypot = SSHHoneypot(port=2222, on_attack=test_callback)
    honeypot.start(threaded=False)
