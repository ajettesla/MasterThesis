import paramiko
import os
from paramiko.config import SSHConfig
import threading

# Thread-safe printing
print_lock = threading.Lock()

def load_ssh_config():
    """Load and parse the SSH config file."""
    ssh_config_file = os.path.expanduser("~/.ssh/config")
    config = SSHConfig()
    if os.path.exists(ssh_config_file):
        with open(ssh_config_file, 'r') as f:
            config.parse(f)
    else:
        raise FileNotFoundError("SSH config file not found at ~/.ssh/config")
    return config

def check_services(client, hostname):
    """Check predefined services based on the hostname."""
    services_to_check = []
    if hostname in ['connt1', 'connt2']:
        services_to_check = ['conntrack_logger']
    elif hostname in ['convsrc5', 'convsrc8']:
        services_to_check = ['tcp_server', 'udp_server']
    else:
        return True  # No checks for other hosts

    all_services_running = True
    for service in services_to_check:
        try:
            stdin, stdout, stderr = client.exec_command(f'systemctl status {service}')
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            # Check if the service is active (running)
            is_running = 'active (running)' in output
            with print_lock:
                print(f"Service {service} on {hostname}: {'running' if is_running else 'not running'}")
            if not is_running:
                with print_lock:
                    print(f"Error details for {service} on {hostname}: {error or 'No error output'}")
                all_services_running = False
        except Exception as e:
            with print_lock:
                print(f"Failed to check {service} on {hostname}: {str(e)}")
            all_services_running = False
    return all_services_running

def connect_to_host(hostname):
    """Attempt to connect to a host, check services, and execute a simple command."""
    try:
        # Load SSH config
        config = load_ssh_config()
        host_config = config.lookup(hostname)

        if not host_config:
            with print_lock:
                print(f"No configuration found for {hostname}")
            return

        # Initialize SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Extract connection details from SSH config
        connect_kwargs = {
            'hostname': host_config.get('hostname', hostname),
            'username': host_config.get('user'),
            'port': int(host_config.get('port', 22)),
            'timeout': 10
        }

        # Handle ProxyJump if specified
        if 'proxyjump' in host_config:
            proxy_host = host_config['proxyjump']
            proxy_config = config.lookup(proxy_host)
            
            proxy_client = paramiko.SSHClient()
            proxy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            proxy_client.connect(
                hostname=proxy_config.get('hostname', proxy_host),
                username=proxy_config.get('user'),
                port=int(proxy_config.get('port', 22)),
                timeout=10
            )
            proxy_transport = proxy_client.get_transport()
            
            dest_addr = (connect_kwargs['hostname'], connect_kwargs['port'])
            local_addr = ('127.0.0.1', 0)
            proxy_channel = proxy_transport.open_channel('direct-tcpip', dest_addr, local_addr)
            
            connect_kwargs['sock'] = proxy_channel

        # Connect to the host
        client.connect(**connect_kwargs)
        with print_lock:
            print(f"Successfully connected to {hostname}")

        # Perform predefined service checks
        services_ok = check_services(client, hostname)
        if not services_ok:
            with print_lock:
                print(f"One or more services are not running on {hostname}. Proceeding with hostname check.")

        # Execute the hostname command
        stdin, stdout, stderr = client.exec_command('hostname')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        with print_lock:
            if output:
                print(f"Hostname output from {hostname}: {output}")
            if error:
                print(f"Error from {hostname}: {error}")

    except paramiko.AuthenticationException:
        with print_lock:
            print(f"Authentication failed for {hostname}")
    except paramiko.SSHException as ssh_err:
        with print_lock:
            print(f"SSH error for {hostname}: {str(ssh_err)}")
    except Exception as e:
        with print_lock:
            print(f"Failed to connect to {hostname}: {str(e)}")
    finally:
        client.close()
        if 'proxy_client' in locals():
            proxy_client.close()

def main():
    # List of hosts to connect to
    hosts = ['connt1', 'connt2', 'convsrc1', 'convsrc2', 'convsrc5', 'convsrc8']
    
    # Create a thread for each host
    threads = []
    for host in hosts:
        with print_lock:
            print(f"\nStarting thread to connect to {host}...")
        thread = threading.Thread(target=connect_to_host, args=(host,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    with print_lock:
        print("\nAll connections completed.")

if __name__ == "__main__":
    main()
