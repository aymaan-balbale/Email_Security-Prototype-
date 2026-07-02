import socket

def run_mock_smtp():
    HOST = '127.0.0.1'
    PORT = 1025
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Mock Strict SMTP Gateway listening on {HOST}:{PORT}...")
        
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection received from {addr}")
            conn.sendall(b"220 mock.gateway.local ESMTP\r\n")
            
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                
                cmd = data.decode('utf-8', errors='ignore').strip()
                print(f"    <- {cmd}")
                
                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    conn.sendall(b"250 Hello\r\n")
                elif cmd.startswith("MAIL FROM"):
                    conn.sendall(b"250 Sender OK\r\n")
                elif cmd.startswith("RCPT TO"):
                    conn.sendall(b"250 Recipient OK\r\n")
                elif cmd.startswith("DATA"):
                    conn.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                elif cmd == "." or cmd.endswith("."):
                    conn.sendall(b"550 5.7.1 Unauthenticated email is not accepted due to DMARC policy.\r\n")
                elif cmd.startswith("QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break

if __name__ == '__main__':
    run_mock_smtp()
