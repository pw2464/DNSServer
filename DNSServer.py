import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Lookup details on fernet in the cryptography.io documentation    
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8')) #call the Fernet encrypt method
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data) #call the Fernet decrypt method
    return decrypted_data.decode('utf-8')

salt = b'Tandon' # Remember it should be a byte-object
password = 'pw2464@nyu.edu'
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt) # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function

# For future use    
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', #mname
            'admin.example.com.', #rname
            2023081401, #serial
            3600, #refresh
            1800, #retry
            604800, #expire
            86400, #minimum
        ),
    },
   
    # Add more records as needed (see assignment instructions!
}
def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port 53 (or 5353 for non-root)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))  # change to 5353 if you don't want to use sudo

    while True:
        try:
            data, addr = server_socket.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            # Ensure there's a question
            if not request.question:
                server_socket.sendto(response.to_wire(), addr)
                continue

            question = request.question[0]
            # normalize qname to a lower-case FQDN with trailing dot
            qname = question.name.to_text().lower()
            qtype = question.rdtype

            # Debug print
            print("Responding to request:", qname, "type:", dns.rdatatype.to_text(qtype))

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]

                # Build rrsets robustly using dns.rrset.from_text where possible
                if qtype == dns.rdatatype.MX:
                    # MX entries are tuples of (priority, exchange)
                    for pref, exch in answer_data:
                        # Construct RRset via from_text - supply "pref exchange" text
                        rr = dns.rrset.from_text(qname, 300, 'IN', 'MX', f"{pref} {exch}")
                        response.answer.append(rr)
                elif qtype == dns.rdatatype.SOA:
                    # SOA stored as tuple: (mname, rname, serial, refresh, retry, expire, minimum)
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    # Make an SOA rdata text string the way from_text expects: "mname rname serial refresh retry expire minimum"
                    soa_text = f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                    rr = dns.rrset.from_text(qname, 300, 'IN', 'SOA', soa_text)
                    response.answer.append(rr)
                else:
                    # answer_data might be a single string or a tuple/list of strings (e.g., TXT)
                    if isinstance(answer_data, (list, tuple)):
                        for item in answer_data:
                            # For TXT records, ensure the string will be quoted correctly by from_text
                            # from_text will quote automatically for TXT if you pass it a single token,
                            # but to be safe for spaces we wrap with quotes here:
                            if qtype == dns.rdatatype.TXT:
                                # ensure quotes in the text form
                                text_val = f'"{item}"' if not (item.startswith('"') and item.endswith('"')) else item
                                rr = dns.rrset.from_text(qname, 300, 'IN', 'TXT', text_val)
                            else:
                                rr = dns.rrset.from_text(qname, 300, 'IN', dns.rdatatype.to_text(qtype), item)
                            response.answer.append(rr)
                    else:
                        # single string
                        if qtype == dns.rdatatype.TXT:
                            text_val = f'"{answer_data}"' if not (answer_data.startswith('"') and answer_data.endswith('"')) else answer_data
                            rr = dns.rrset.from_text(qname, 300, 'IN', 'TXT', text_val)
                        else:
                            rr = dns.rrset.from_text(qname, 300, 'IN', dns.rdatatype.to_text(qtype), answer_data)
                        response.answer.append(rr)

            # Set AA flag
            response.flags |= (1 << 10)

            # Send the response
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting... (KeyboardInterrupt)')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            # Keep server alive and print a helpful debug message
            print("Error handling request:", repr(e))



def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()
    #print("Encrypted Value:", encrypted_value)
    #print("Decrypted Value:", decrypted_value) 
