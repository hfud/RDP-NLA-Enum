import socket
import struct
import sys
import argparse
import time

class RDPProtocolChecker:
    def __init__(self, host, port=3389, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        
        # Định nghĩa các protocol theo script NSE gốc
        self.PROTOCOLS = {
            "Native RDP": 0,
            "SSL": 1, 
            "CredSSP (NLA)": 3,
            "RDSTLS": 4,
            "CredSSP with Early User Auth": 8
        }

    def create_connection_request(self, protocol_type=0):
        """Tạo gói tin Connection Request theo chuẩn RDP - FIXED"""
        # TPKT Header (RFC 1006 Section 6)
        tpkt_header = struct.pack('>BBH', 3, 0, 19)  # version=3, reserved=0, length=19
        
        # X.224 Connection Request PDU (ITU-T X.224)
        # LI=14 (0x0E), CR CDT=Connection Request (0xE0)
        x224_header = struct.pack('B', 0x0E)  # Length Indicator = 14
        x224_cr = struct.pack('B', 0xE0)      # Connection Request
        x224_cr += struct.pack('>H', 0)       # DST-REF = 0
        x224_cr += struct.pack('>H', 0)       # SRC-REF = 0  
        x224_cr += struct.pack('B', 0)        # Class Option = 0
        
        # RDP Negotiation Request (MS-RDPBCGR 2.2.1.1)
        neg_req = struct.pack('<B', 0x01)     # TYPE_RDP_NEG_REQ
        neg_req += struct.pack('<B', 0)       # flags = 0
        neg_req += struct.pack('<H', 8)       # length = 8
        neg_req += struct.pack('<I', protocol_type)  # requestedProtocols
        
        return tpkt_header + x224_header + x224_cr + neg_req

    def parse_negotiation_response(self, data):
        """Phân tích phản hồi negotiation từ server - IMPROVED"""
        try:
            if len(data) < 11:
                return None, "Response too short"
                
            # Parse TPKT header
            if len(data) < 4:
                return None, "No TPKT header"
                
            tpkt_version, _, tpkt_length = struct.unpack('>BBH', data[0:4])
            if tpkt_version != 3:
                return None, f"Invalid TPKT version: {tpkt_version}"
            
            # Parse X.224 Connection Confirm
            if len(data) < 7:
                return None, "No X.224 header"
                
            x224_li = data[4]  # Length Indicator
            x224_cc = data[5]  # CC CDT (should be 0xD0 for Connection Confirm)
            
            # Tìm RDP Negotiation Response
            if len(data) < 4 + x224_li + 8:
                # Server không gửi negotiation data (chấp nhận kết nối mà không cần negotiation)
                return 2, "Success (no negotiation data)"
            
            neg_data_start = 4 + x224_li
            neg_data = data[neg_data_start:]
            
            if len(neg_data) < 8:
                return 2, "Success (short negotiation)"
            
            neg_type, flags, length = struct.unpack('<BBH', neg_data[0:4])
            
            if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
                result = struct.unpack('<I', neg_data[4:8])[0]
                return result, "Success"
            elif neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
                error_code = struct.unpack('<I', neg_data[4:8])[0]
                return error_code, f"Failure code: {error_code}"
            else:
                # Không phải negotiation response, có thể server chấp nhận kết nối trực tiếp
                return 2, "Success (direct connection)"
                
        except Exception as e:
            return None, f"Parse error: {str(e)}"

    def test_protocol_improved(self, protocol_name, protocol_value):
        """Kiểm tra một protocol cụ thể - IMPROVED VERSION"""
        print(f"  Testing {protocol_name:<35}...", end="", flush=True)
        
        try:
            # Tạo socket và kết nối
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Gửi Connection Request với protocol cụ thể
            request = self.create_connection_request(protocol_value)
            sock.send(request)
            
            # Nhận phản hồi - đọc toàn bộ data có sẵn
            response = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    # Nếu đã nhận đủ data, thoát
                    if len(response) >= 1024:
                        break
            except socket.timeout:
                # Timeout khi đọc là bình thường
                pass
            except BlockingIOError:
                pass
            
            sock.close()
            
            # Phân tích phản hồi
            result, message = self.parse_negotiation_response(response)
            
            if result == 2:  # SUCCESS
                print(" SUCCESS")
                return True, protocol_name
            elif result is not None:
                print(f" FAILED (Code: {result})")
            else:
                # Kiểm tra nếu có response data (có thể server chấp nhận mà không cần negotiation)
                if len(response) > 0:
                    print(" SUCCESS (with data)")
                    return True, protocol_name
                else:
                    print(" NO RESPONSE")
                
            return False, None
            
        except socket.timeout:
            print(" TIMEOUT")
            return False, None
        except ConnectionRefusedError:
            print(" CONNECTION REFUSED")
            return False, None
        except Exception as e:
            print(f" ERROR: {str(e)}")
            return False, None

    def check_protocols_comprehensive(self):
        """Kiểm tra tất cả các protocol - COMPREHENSIVE VERSION"""
        print(f"[*] Comprehensive RDP Protocol Scan for {self.host}:{self.port}")
        print(f"[*] Timeout: {self.timeout}s")
        print()
        
        supported_protocols = []
        nla_supported = False
        
        for protocol_name, protocol_value in self.PROTOCOLS.items():
            time.sleep(0.3)  # Giảm tốc độ để tăng độ tin cậy
            
            success, proto_name = self.test_protocol_improved(protocol_name, protocol_value)
            if success:
                supported_protocols.append(proto_name)
                if "NLA" in proto_name:
                    nla_supported = True
        
        # Hiển thị kết quả chi tiết
        print(f"\n" + "="*60)
        print(f"[*] SCAN RESULTS:")
        print(f"    Target: {self.host}:{self.port}")
        print(f"    Supported protocols: {len(supported_protocols)}")
        
        for proto in supported_protocols:
            print(f"      - {proto}")
            
        print(f"    NLA Enabled: {'YES' if nla_supported else 'NO'}")
        
        # Đánh giá bảo mật
        if nla_supported:
            print(f"    Security Assessment: GOOD (NLA provides additional security)")
        else:
            print(f"    Security Assessment: WARNING (NLA not enabled)")
        
        return nla_supported, supported_protocols

    def quick_nla_check(self):
        """Chỉ kiểm tra nhanh NLA - IMPROVED"""
        print(f"[*] Quick NLA check for {self.host}:{self.port}")
        success, _ = self.test_protocol_improved("CredSSP (NLA)", self.PROTOCOLS["CredSSP (NLA)"])
        
        if success:
            print(f"\n[+] NLA is ENABLED on {self.host}:{self.port}")
        else:
            print(f"\n[-] NLA is NOT enabled on {self.host}:{self.port}")
        
        return success

def main():
    parser = argparse.ArgumentParser(description='RDP Protocol Scanner - FIXED VERSION')
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick NLA check only')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    checker = RDPProtocolChecker(args.host, args.port, args.timeout)
    
    if args.quick:
        nla_enabled = checker.quick_nla_check()
    else:
        nla_enabled, protocols = checker.check_protocols_comprehensive()
    
    # Return exit code
    sys.exit(0 if nla_enabled else 1)

if __name__ == "__main__":
    main()