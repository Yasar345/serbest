from scapy.all import IP, TCP, UDP, sr1
import threading
import sys
import time

# Məşhur portlar ve adları
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL"
}

# Nəticələri qeyd etmək üçün siyahı
results = []

def tcp_scan(target_ip, port):
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(pkt, timeout=1, verbose=0)

    if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
        service = COMMON_PORTS.get(port, "Unknown Service")
        result = f"[+] TCP Port {port} ({service}) is OPEN"
        print(result)
        results.append(result)
        # Bağlantıyı kapatmak için RST paketi gönderelim
        rst_pkt = IP(dst=target_ip) / TCP(dport=port, flags="R")
        sr1(rst_pkt, timeout=1, verbose=0)

def udp_scan(target_ip, port):
    pkt = IP(dst=target_ip) / UDP(dport=port)
    response = sr1(pkt, timeout=1, verbose=0)

    if not response:
        service = COMMON_PORTS.get(port, "Unknown Service")
        result = f"[+] UDP Port {port} ({service}) is OPEN or FILTERED"
        print(result)
        results.append(result)
    elif response.haslayer(UDP):
        result = f"[+] UDP Port {port} is OPEN"
        print(result)
        results.append(result)
    else:
        result = f"[-] UDP Port {port} is CLOSED or FILTERED"
        results.append(result)

def port_scan(target_ip, ports, scan_type="TCP", thread_count=10, output_file="scan_results.txt"):
    print(f"Scanning target: {target_ip} with {scan_type} scan")
    threads = []

    for port in ports:
        if scan_type.upper() == "TCP":
            t = threading.Thread(target=tcp_scan, args=(target_ip, port))
        elif scan_type.upper() == "UDP":
            t = threading.Thread(target=udp_scan, args=(target_ip, port))
        else:
            print("Invalid scan type. Use 'TCP' or 'UDP'.")
            return

        threads.append(t)
        t.start()

        # Thread sayını yoxlayaq
        if len(threads) >= thread_count:
            for thread in threads:
                thread.join()
            threads = []

    # Qalan thread'leri gözləyək
    for thread in threads:
        thread.join()

    # Nəticələri fayla yazaq
    with open(output_file, "w") as file:
        file.write(f"Scan results for target: {target_ip} ({scan_type} scan)\n")
        file.write("-" * 50 + "\n")
        for result in results:
            file.write(result + "\n")
        file.write(f"\nScan completed in {time.time() - start_time:.2f} seconds.\n")

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    target = input("Enter target IP address: ")
    ports = range(20, 1025)
    scan_type = input("Enter scan type (TCP/UDP): ")
    output_file = input("Enter output file name (default: scan_results.txt): ") or "scan_results.txt"

    start_time = time.time()
    port_scan(target, ports, scan_type=scan_type, thread_count=50, output_file=output_file)
    end_time = time.time()

    print(f"Scan completed in {end_time - start_time:.2f} seconds.")
