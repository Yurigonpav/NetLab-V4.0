import socket
import ipaddress
import subprocess
import re
import platform
import os

def test_powershell(ip_local):
    print(f"Testing PowerShell for {ip_local}...")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-NetIPAddress -IPAddress '{ip_local}' -AddressFamily IPv4).PrefixLength"],
            capture_output=True, text=True, timeout=5
        )
        out = proc.stdout.strip()
        if out.isdigit():
            prefix = int(out)
            return str(ipaddress.ip_network(f"{ip_local}/{prefix}", strict=False))
        return f"Fail (Output: {out})"
    except Exception as e:
        return f"Error: {e}"

def test_ipconfig(ip_local):
    print(f"Testing ipconfig /all for {ip_local}...")
    try:
        proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=5)
        out = proc.stdout
        idx = out.find(ip_local)
        if idx == -1: return "IP not found in ipconfig"
        trecho = out[max(0, idx-400):idx+400]
        m = re.search(r"M[aá]scara[^:]*:\s*((?:\d+\.){3}\d+)", trecho, re.I)
        if m:
            mask = m.group(1)
            return str(ipaddress.ip_network(f"{ip_local}/{mask}", strict=False))
        return "Mask pattern not found"
    except Exception as e:
        return f"Error: {e}"

def test_psutil(ip_local):
    print(f"Testing psutil for {ip_local}...")
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip_local:
                    mask = addr.netmask
                    if mask:
                        return str(ipaddress.ip_network(f"{ip_local}/{mask}", strict=False))
        return "IP not found in psutil"
    except ImportError:
        return "psutil not installed"
    except Exception as e:
        return f"Error: {e}"

def test_wmi(ip_local):
    print(f"Testing WMI (PowerShell) for {ip_local}...")
    try:
        cmd = f"(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {{$_.IPAddress -contains '{ip_local}'}}).IPSubnet[0]"
        proc = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        if out and '.' in out:
            return str(ipaddress.ip_network(f"{ip_local}/{out}", strict=False))
        return f"Fail (Output: {out})"
    except Exception as e:
        return f"Error: {e}"

def test_arp_gateway(ip_local):
    print(f"Testing ARP Gateway Inference for {ip_local}...")
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.(?:1|254))\s+", line)
            if m:
                gw = m.group(1)
                if gw.split('.')[:3] == ip_local.split('.')[:3]:
                    return f"{'.'.join(ip_local.split('.')[:3])}.0/24 (Inferred from GW {gw})"
        return "No standard gateway found in ARP table"
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    ip = socket.gethostbyname(socket.gethostname())
    # Try more robust IP detection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except: pass

    print(f"=== NetLab CIDR Diagnostic Tool ===")
    print(f"System: {platform.platform()}")
    print(f"Local IP: {ip}")
    print("-" * 40)
    
    results = {
        "PowerShell (Prefix)": test_powershell(ip),
        "ipconfig (Parsing)": test_ipconfig(ip),
        "psutil (Library)": test_psutil(ip),
        "WMI (Legacy)": test_wmi(ip),
        "ARP Gateway (Logic)": test_arp_gateway(ip),
        "RFC 1918 (Fallback)": f"{'.'.join(ip.split('.')[:3])}.0/24" if ipaddress.ip_address(ip).is_private else "Not Private"
    }

    for name, res in results.items():
        print(f"{name:20}: {res}")
    print("-" * 40)
