#!/usr/bin/env python3
import argparse
import socket
import socketserver
import ssl
import struct
import datetime
import sys
import os
import uuid

import hmac
import hashlib
import base64
from plugins import auth_pb2

HOST = "0.0.0.0"
PORT = 5566

# Authentication configuration (loaded from environment variables)
ENABLE_TLS = os.getenv("ENABLE_TLS", "false").lower() == "true"
ENABLE_AUTHENTICATION = os.getenv("ENABLE_AUTHENTICATION", "false").lower() == "true"
NFCGATE_SECRET = os.getenv("NFCGATE_SECRET", "")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
ALLOW_PLAINTEXT_AUTH = os.getenv("ALLOW_PLAINTEXT_AUTH", "false").lower() == "true"


# ==================== Authentication Helper Functions ====================

def verify_hmac(secret, nonce, client_hmac):
    """
    Verify HMAC challenge-response.
    
    Args:
        secret: Shared secret string
        nonce: Server-generated nonce
        client_hmac: HMAC sent by client (hex string)
    
    Returns:
        True if HMAC is valid, False otherwise
    """
    if not secret:
        return False
    
    expected_hmac = hmac.new(
        secret.encode('utf-8'),
        nonce.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_hmac, client_hmac)


def create_session(client_ip):
    """
    Create a new session for an authenticated client.
    
    Args:
        client_ip: IP address of the client
    
    Returns:
        Dictionary with session_id and session data
    """
    session_id = uuid.uuid4().hex
    now = datetime.datetime.now()
    expires = now + datetime.timedelta(seconds=SESSION_TTL_SECONDS)
    
    session_data = {
        "client_ip": str(client_ip),
        "created": now,
        "expires": expires
    }
    
    return session_id, session_data


def is_session_valid(sessions, session_id, client_ip):
    """
    Check if a session is valid and not expired.
    
    Args:
        sessions: Dictionary of active sessions
        session_id: Session ID to check
        client_ip: IP address to validate against
    
    Returns:
        True if session is valid, False otherwise
    """
    if session_id not in sessions:
        return False
    
    session = sessions[session_id]
    
    # Check IP match
    if session["client_ip"] != str(client_ip):
        return False
    
    # Check expiry
    if datetime.datetime.now() > session["expires"]:
        return False
    
    return True


class PluginHandler:
    def __init__(self, plugins):
        self.plugin_list = []

        for modname in plugins:
            self.plugin_list.append((modname, __import__("plugins.mod_%s" % modname, fromlist=["plugins"])))
            print("Loaded", "mod_%s" % modname)

    def filter(self, client, data):
        for modname, plugin in self.plugin_list:
            if type(data) == list:
                first = data[0]
            else:
                first = data
            first = plugin.handle_data(lambda *x: client.log(*x, tag=modname), first, client.state)
            if type(data) == list:
                data = [first] + data[1:]
            else:
                data = first

        return data


class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, srv):
        super().__init__(request, client_address, srv)
        
    def log(self, *args, tag="server"):
        self.server.log(*args, origin=self.client_address, tag=tag)

    def _perform_authentication(self):
        """
        Perform the authentication handshake with the client.
        
        Returns:
            True if authentication succeeds, False otherwise
        """
        client_ip = self.client_address[0]
        
        # Check rate limiting
        if not self.server.check_rate_limit(client_ip):
            self.log("Rate limit exceeded for authentication attempts", tag="auth")
            self._send_auth_result(False, "", "rate_limit_exceeded")
            return False
        
        try:
            # Generate and send challenge
            nonce = uuid.uuid4().hex
            self.log("Sending auth challenge", tag="auth")
            self._send_auth_challenge(nonce)
            
            # Wait for response (with timeout)
            self.request.settimeout(30)  # 30 second timeout for auth
            response = self._receive_auth_response()
            
            if response is None:
                self.log("Failed to receive auth response", tag="auth")
                self._send_auth_result(False, "", "timeout_or_invalid_response")
                return False
            
            # Verify HMAC
            client_id = response.client_id
            client_hmac = response.hmac
            
            self.log("Received auth response from client: {}".format(client_id), tag="auth")
            
            if not verify_hmac(NFCGATE_SECRET, nonce, client_hmac):
                self.log("HMAC verification failed for client: {}".format(client_id), tag="auth")
                self._send_auth_result(False, "", "invalid_hmac")
                return False
            
            # Authentication successful - create session
            session_id = self.server.create_auth_session(client_ip)
            self._send_auth_result(True, session_id, "")
            self.log("Authentication successful for client: {}".format(client_id), tag="auth")
            
            # Restore normal timeout
            self.request.settimeout(300)
            return True
            
        except socket.timeout:
            self.log("Authentication timeout", tag="auth")
            return False
        except Exception as e:
            self.log("Authentication error: {}".format(str(e)), tag="auth")
            return False

    def _send_auth_challenge(self, nonce):
        """Send AuthChallenge message to client."""
        if not nonce:
            self.log("Nonce is not set or empty, cannot send auth challenge", tag="auth")
            raise ValueError("Nonce must be set and not empty before serialization")
        challenge = auth_pb2.AuthChallenge()
        challenge.nonce = nonce
        msg_bytes = challenge.SerializeToString()
        self.log(f"AuthChallenge raw bytes: {msg_bytes.hex()}", tag="auth")
        self.log(f"AuthChallenge base64: {base64.b64encode(msg_bytes).decode()}", tag="auth")
        self.log(f"AuthChallenge length: {len(msg_bytes)}", tag="auth")
        total_len = len(msg_bytes) + 1  # 1 byte for type
        self.wfile.write(struct.pack("!IB", total_len, 255))
        self.wfile.write(msg_bytes)

    def _receive_auth_response(self):
        """Receive and parse AuthResponse from client."""
        try:
            msg_len_data = self.rfile.read(5)
            if len(msg_len_data) < 5:
                return None
            
            msg_len, msg_type = struct.unpack("!IB", msg_len_data)
            
            # Expect auth response (msg_type should be 255)
            if msg_type != 255:
                self.log("Unexpected message type during auth: {}".format(msg_type), tag="auth")
                return None
            
            data = self.rfile.read(msg_len)
            if len(data) < msg_len:
                return None
            
            response = auth_pb2.AuthResponse()
            response.ParseFromString(data)
            return response
            
        except Exception as e:
            self.log("Error receiving auth response: {}".format(str(e)), tag="auth")
            return None

    def _send_auth_result(self, success, session_id, reason):
        """Send AuthResult message to client."""
        try:
            result = auth_pb2.AuthResult()
            result.success = success
            if session_id:
                result.session_id = session_id
            if reason:
                result.reason = reason
            
            msg_bytes = result.SerializeToString()
            total_len = len(msg_bytes) + 1  # 1 byte for type
            self.wfile.write(struct.pack("!IB", total_len, 255))
            self.wfile.write(msg_bytes)
        except Exception as e:
            self.log("Error sending auth result: {}".format(str(e)), tag="auth")

    def setup(self):
        super().setup()
        
        self.session = None
        self.state = {}
        self.authenticated = False  # Track authentication status
        self.request.settimeout(300)
        self.log("server", "connected")
        
        # Perform authentication handshake if enabled
        if self.server.auth_enabled:
            self.authenticated = self._perform_authentication()
            if not self.authenticated:
                self.log("Authentication failed, closing connection", tag="auth")
                # Connection will be closed after setup completes

    def handle(self):
        super().handle()
        
        # If authentication is enabled and client is not authenticated, close connection
        if self.server.auth_enabled and not self.authenticated:
            self.log("Rejecting unauthenticated connection", tag="auth")
            return

        while True:
            try:
                msg_len_data = self.rfile.read(5)
            except socket.timeout:
                self.log("server", "Timeout")
                break
            if len(msg_len_data) < 5:
                break

            msg_len, session = struct.unpack("!IB", msg_len_data)
            data = self.rfile.read(msg_len)
            self.log("server", "data:", bytes(data))

            # no data was sent or no session number supplied and none set yet
            if msg_len == 0 or session == 0 and self.session is None:
                break

            # change in session number detected
            if self.session != session:
                # remove from old association
                self.server.remove_client(self, self.session)
                # update and add association
                self.session = session
                self.server.add_client(self, session)

            # allow plugins to filter data before sending it to all clients in the session
            self.server.send_to_clients(self.session, self.server.plugins.filter(self, data), self)

    def finish(self):
        super().finish()

        self.server.remove_client(self, self.session)
        self.log("server", "disconnected")


class NFCGateServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, request_handler, plugins, tls_options=None, bind_and_activate=True):
        self.allow_reuse_address = True
        super().__init__(server_address, request_handler, bind_and_activate)

        self.clients = {}
        self.plugins = PluginHandler(plugins)
        
        # Authentication state
        self.sessions = {}  # session_id -> session_data
        self.auth_enabled = False
        self.auth_attempts = {}  # IP -> (count, last_attempt_time) for rate limiting

        # TLS
        self.tls_options = tls_options
        
        # Validate and configure authentication
        self._configure_authentication()

        self.log("NFCGate server listening on", server_address)
        if self.tls_options:
            self.log("TLS enabled with cert {} and key {}".format(self.tls_options["cert_file"],
                                                                  self.tls_options["key_file"]))

    def get_request(self):
        client_socket, from_addr = super().get_request()
        if not self.tls_options:
            return client_socket, from_addr
        # if TLS enabled, wrap the socket
        return self.tls_options["context"].wrap_socket(client_socket, server_side=True), from_addr

    def log(self, *args, origin="0", tag="server"):
        print(datetime.datetime.now(), "["+tag+"]", origin, *args)

    def _configure_authentication(self):
        """
        Configure authentication based on environment variables.
        Validates requirements and sets auth_enabled flag.
        """
        if not ENABLE_AUTHENTICATION:
            self.auth_enabled = False
            self.log("Authentication is disabled")
            return
        
        # Check if TLS is enabled
        if not self.tls_options and not ALLOW_PLAINTEXT_AUTH:
            self.log("WARNING: Authentication requires TLS but TLS is not enabled.", tag="auth")
            self.log("WARNING: Authentication has been disabled for security reasons.", tag="auth")
            self.log("WARNING: Set ALLOW_PLAINTEXT_AUTH=true to override (NOT RECOMMENDED).", tag="auth")
            self.auth_enabled = False
            return
        
        # Check if secret is set
        if not NFCGATE_SECRET:
            self.log("ERROR: NFCGATE_SECRET is not set but authentication is enabled.", tag="auth")
            self.log("ERROR: Authentication has been disabled.", tag="auth")
            self.auth_enabled = False
            return
        
        # All checks passed
        self.auth_enabled = True
        if not self.tls_options:
            self.log("WARNING: Authentication is enabled over PLAINTEXT connection!", tag="auth")
            self.log("WARNING: This is INSECURE and should only be used for testing.", tag="auth")
        else:
            self.log("Authentication is enabled with session TTL of {} seconds".format(SESSION_TTL_SECONDS), tag="auth")

    def check_rate_limit(self, client_ip):
        """
        Basic rate limiting for authentication attempts.
        
        Args:
            client_ip: IP address to check
        
        Returns:
            True if request is allowed, False if rate limited
        """
        now = datetime.datetime.now()
        max_attempts = 5
        window_seconds = 60
        
        if client_ip not in self.auth_attempts:
            self.auth_attempts[client_ip] = (1, now)
            return True
        
        count, last_attempt = self.auth_attempts[client_ip]
        
        # Reset if window has passed
        if (now - last_attempt).total_seconds() > window_seconds:
            self.auth_attempts[client_ip] = (1, now)
            return True
        
        # Increment and check limit
        count += 1
        self.auth_attempts[client_ip] = (count, now)
        
        if count > max_attempts:
            return False
        
        return True

    def create_auth_session(self, client_ip):
        """
        Create and register a new authentication session.
        
        Args:
            client_ip: IP address of the authenticated client
        
        Returns:
            session_id string
        """
        session_id, session_data = create_session(client_ip)
        self.sessions[session_id] = session_data
        self.log("Created session {} for {}".format(session_id[:8], client_ip), tag="auth")
        return session_id

    def cleanup_expired_sessions(self):
        """Remove expired sessions from the sessions dict."""
        now = datetime.datetime.now()
        expired = [sid for sid, data in self.sessions.items() if now > data["expires"]]
        for sid in expired:
            del self.sessions[sid]
            self.log("Removed expired session {}".format(sid[:8]), tag="auth")

    def add_client(self, client, session):
        if session is None:
            return

        if session not in self.clients:
            self.clients[session] = []

        self.clients[session].append(client)
        client.log("joined session", session)

    def remove_client(self, client, session):
        if session is None or session not in self.clients:
            return

        self.clients[session].remove(client)
        client.log("left session", session)

    def send_to_clients(self, session, msgs, origin):
        if session is None or session not in self.clients:
            return

        for client in self.clients[session]:
            # do not send message back to originator
            if client is origin:
                continue

            if type(msgs) != list:
                msgs = [msgs]

            for msg in msgs:
                # Use session as type byte (or set a specific type if needed)
                total_len = len(msg) + 1
                client.wfile.write(struct.pack('!IB', total_len, session if isinstance(session, int) else 0))
                client.wfile.write(msg)

        self.log("Publish reached", len(self.clients[session]) - 1, "clients")


def parse_args():
    parser = argparse.ArgumentParser(prog="NFCGate server")
    parser.add_argument("plugins", type=str, nargs="*", help="List of plugin modules to load.")
    parser.add_argument("-s", "--tls", help="Enable TLS. You must specify certificate and key.",
                        default=False, action="store_true")
    parser.add_argument("--tls_cert", help="TLS certificate file in PEM format.", action="store")
    parser.add_argument("--tls_key", help="TLS key file in PEM format.", action="store")

    args = parser.parse_args()
    tls_options = None

    if args.tls:
        # check cert and key file
        if args.tls_cert is None or args.tls_key is None:
            print("You must specify tls_cert and tls_key!")
            sys.exit(1)

        tls_options = {
            "cert_file": args.tls_cert,
            "key_file": args.tls_key
        }
        try:
            tls_options["context"] = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            tls_options["context"].load_cert_chain(tls_options["cert_file"], tls_options["key_file"])
        except ssl.SSLError:
            print("Certificate or key could not be loaded. Please check format and file permissions!")
            sys.exit(1)
    return args.plugins, tls_options


def main():
    plugins, tls_options = parse_args()
    NFCGateServer((HOST, PORT), NFCGateClientHandler, plugins, tls_options).serve_forever()


if __name__ == "__main__":
    main()
