"""
SSH Honeypot - Fake SSH Server
Captures credentials and commands from attackers using Paramiko
"""

import os
import sys
import socket
import threading
import uuid
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

try:
    import paramiko
    from paramiko import RSAKey
except ImportError:
    print("Error: paramiko is required. Install with: pip install paramiko")
    sys.exit(1)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeShell:
    """Fake shell environment for SSH honeypot"""

    def __init__(self, username: str):
        self.username = username
        self.hostname = 'localhost'
        self.cwd = '/home/' + username if username != 'root' else '/root'
        self.env = {
            'USER': username,
            'HOME': self.cwd,
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'SHELL': '/bin/bash',
        }

        # Fake filesystem structure
        self.filesystem = {
            '/': ['bin', 'etc', 'home', 'root', 'tmp', 'var', 'usr'],
            '/home': ['admin', 'user'],
            '/home/admin': ['.bashrc', '.profile', 'documents'],
            '/home/user': ['.bashrc', '.profile'],
            '/root': ['.bashrc', '.profile', '.ssh'],
            '/etc': ['passwd', 'shadow', 'hosts', 'resolv.conf', 'ssh'],
            '/tmp': [],
            '/var': ['log', 'www'],
            '/var/log': ['syslog', 'auth.log', 'messages'],
        }

        # Fake file contents
        self.file_contents = {
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n',
            '/etc/hosts': '127.0.0.1 localhost\n::1 localhost\n',
            '~/.bashrc': '# .bashrc\nexport PS1="\\u@\\h:\\w\\$ "\n',
        }

    def get_prompt(self) -> str:
        """Get shell prompt"""
        user_char = '#' if self.username == 'root' else '$'
        display_cwd = self.cwd.replace('/home/' + self.username, '~')
        if self.username == 'root':
            display_cwd = self.cwd.replace('/root', '~')
        return f"{self.username}@{self.hostname}:{display_cwd}{user_char} "

    def execute(self, command: str) -> Tuple[str, bool]:
        """
        Execute a fake command

        Returns:
            Tuple of (output, should_exit)
        """
        command = command.strip()
        if not command:
            return '', False

        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Command handlers
        handlers = {
            'ls': self._cmd_ls,
            'cd': self._cmd_cd,
            'pwd': self._cmd_pwd,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'uname': self._cmd_uname,
            'cat': self._cmd_cat,
            'echo': self._cmd_echo,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'logout': self._cmd_exit,
            'help': self._cmd_help,
            'w': self._cmd_w,
            'uptime': self._cmd_uptime,
            'ps': self._cmd_ps,
            'wget': self._cmd_wget,
            'curl': self._cmd_curl,
            'ifconfig': self._cmd_ifconfig,
            'ip': self._cmd_ip,
            'netstat': self._cmd_netstat,
            'history': self._cmd_history,
            'clear': lambda a: ('', False),
        }

        if cmd in handlers:
            return handlers[cmd](args)
        else:
            return f"-bash: {cmd}: command not found\n", False

    def _cmd_ls(self, args: List[str]) -> Tuple[str, bool]:
        path = args[0] if args and not args[0].startswith('-') else self.cwd
        if path in self.filesystem:
            items = self.filesystem[path]
            return '  '.join(items) + '\n' if items else '', False
        return f"ls: cannot access '{path}': No such file or directory\n", False

    def _cmd_cd(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            self.cwd = self.env['HOME']
        elif args[0] == '~':
            self.cwd = self.env['HOME']
        elif args[0] == '..':
            self.cwd = '/'.join(self.cwd.split('/')[:-1]) or '/'
        elif args[0].startswith('/'):
            if args[0] in self.filesystem or args[0].rsplit('/', 1)[0] in self.filesystem:
                self.cwd = args[0]
            else:
                return f"-bash: cd: {args[0]}: No such file or directory\n", False
        else:
            new_path = f"{self.cwd}/{args[0]}".replace('//', '/')
            if new_path in self.filesystem:
                self.cwd = new_path
            else:
                return f"-bash: cd: {args[0]}: No such file or directory\n", False
        return '', False

    def _cmd_pwd(self, args: List[str]) -> Tuple[str, bool]:
        return self.cwd + '\n', False

    def _cmd_whoami(self, args: List[str]) -> Tuple[str, bool]:
        return self.username + '\n', False

    def _cmd_id(self, args: List[str]) -> Tuple[str, bool]:
        if self.username == 'root':
            return 'uid=0(root) gid=0(root) groups=0(root)\n', False
        return f'uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\n', False

    def _cmd_uname(self, args: List[str]) -> Tuple[str, bool]:
        if '-a' in args:
            return 'Linux localhost 5.15.0-generic #1 SMP x86_64 GNU/Linux\n', False
        return 'Linux\n', False

    def _cmd_cat(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return '', False
        for path in args:
            if path in self.file_contents:
                return self.file_contents[path], False
            full_path = path.replace('~', self.env['HOME'])
            if full_path in self.file_contents:
                return self.file_contents[full_path], False
        return f"cat: {args[0]}: No such file or directory\n", False

    def _cmd_echo(self, args: List[str]) -> Tuple[str, bool]:
        return ' '.join(args) + '\n', False

    def _cmd_exit(self, args: List[str]) -> Tuple[str, bool]:
        return 'logout\n', True

    def _cmd_help(self, args: List[str]) -> Tuple[str, bool]:
        return '''Available commands:
  ls, cd, pwd, cat, echo, whoami, id, uname
  ps, w, uptime, ifconfig, ip, netstat
  wget, curl, history, clear, exit
''', False

    def _cmd_w(self, args: List[str]) -> Tuple[str, bool]:
        return f''' 12:00:00 up 1 day,  2:30,  1 user,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{self.username:8} pts/0    :0               10:00    0.00s  0.01s  0.00s w
''', False

    def _cmd_uptime(self, args: List[str]) -> Tuple[str, bool]:
        return ' 12:00:00 up 1 day,  2:30,  1 user,  load average: 0.00, 0.01, 0.05\n', False

    def _cmd_ps(self, args: List[str]) -> Tuple[str, bool]:
        return '''  PID TTY          TIME CMD
    1 ?        00:00:01 init
  100 pts/0    00:00:00 bash
  200 pts/0    00:00:00 ps
''', False

    def _cmd_wget(self, args: List[str]) -> Tuple[str, bool]:
        if args:
            url = args[-1]
            return f"--2024-01-01 12:00:00--  {url}\nResolving... failed: Name or service not known.\nwget: unable to resolve host address\n", False
        return 'wget: missing URL\n', False

    def _cmd_curl(self, args: List[str]) -> Tuple[str, bool]:
        if args:
            url = args[-1]
            return f"curl: (6) Could not resolve host: {url.split('/')[2] if '/' in url else url}\n", False
        return 'curl: try \'curl --help\' for more information\n', False

    def _cmd_ifconfig(self, args: List[str]) -> Tuple[str, bool]:
        return '''eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:11:22:33:44:55  txqueuelen 1000  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
''', False

    def _cmd_ip(self, args: List[str]) -> Tuple[str, bool]:
        if args and args[0] == 'addr':
            return self._cmd_ifconfig([])[0], False
        return 'Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n', False

    def _cmd_netstat(self, args: List[str]) -> Tuple[str, bool]:
        return '''Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
''', False

    def _cmd_history(self, args: List[str]) -> Tuple[str, bool]:
        return '    1  ls\n    2  pwd\n    3  history\n', False


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
        """Handle command execution"""
        if self.on_attack:
            self.on_attack(
                source='SSH',
                ip_address=ip_address,
                command=command,
                session_id=session_id,
                extra_data={'type': 'command'}
            )

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

            # Send welcome message
            channel.send(f"Welcome to Ubuntu 22.04.1 LTS\n\n")
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
                            if command_buffer.strip():
                                # Log command
                                self._sessions[session_id]['commands'].append(command_buffer)
                                self._handle_command(client_ip, command_buffer, session_id)

                                # Execute command
                                output, should_exit = shell.execute(command_buffer)
                                if output:
                                    channel.send(output.replace('\n', '\r\n'))

                                if should_exit:
                                    channel.close()
                                    break

                            command_buffer = ""
                            channel.send('\r\n' + shell.get_prompt())

                        elif char == '\x7f' or char == '\x08':  # Backspace
                            if command_buffer:
                                command_buffer = command_buffer[:-1]
                                channel.send('\b \b')

                        elif char == '\x03':  # Ctrl+C
                            command_buffer = ""
                            channel.send('^C\r\n' + shell.get_prompt())

                        elif char == '\x04':  # Ctrl+D
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
