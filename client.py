import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
from encrypt_decrypt_funcs import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_HANDSHAKE = 4


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks

        ## Diffie-Hellman
        self.parameters = dh.generate_parameters(generator=2, key_size=512,
                                    backend=default_backend())
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.derived_key = ''

        ## Cipher-suite
        self.cipher = ''
        self.mode = ''
        self.sintese = ''
        

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        #################Establishing ciphersuite
        algString='DH;'
        #####

        alg=input("Encryption Algorithm?\n1)AES-128\n2)3DES\n")
        alg=int(alg)
        if alg not in (1,2):
            exit(0)
        if alg==1:
            self.cipher="AES-128"
        else:
            self.cipher="3DES"

        algString+=self.cipher+";"

        #####
        if alg==1:
            mode=input("Encryption mode?\n1)CBC\n2)GCM\n")
        else:
            mode=input("Encryption mode?\n1)CBC\n2)ECB\n")
        mode=int(mode)
        if mode not in (1,2):
            exit(0)
        if mode==1:
            self.mode="CBC"
        else:
            if alg==1:
                self.mode="GCM"
            else:
                self.mode="ECB"

        algString+=self.mode + ";"
        #####
        integ=input("Integrity control?\n1)SHA-256\n2)SHA-512\n")
        integ=int(integ)
        if integ not in (1,2):
            exit(0)
        if integ==1:
            self.sintese = 'SHA-256'
        else:
            self.sintese = 'SHA-512'

        algString+=self.sintese
        #####
        print(algString)
        #######################################

        self.transport = transport


        ## Starting handshake
        sendable_params = base64.b64encode(self.parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)).decode()
        sendable_key = base64.b64encode(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).decode()
        
        message = {'type': 'ALGORITHMS', 'alg_list': algString, 'params': sendable_params, 'public_key' : sendable_key}
        self._send(message)
        logger.debug('Sent ciphersuite and handshake data to server')
        #

        message = {'type': 'OPEN', 'file_name': self.file_name}
        self._send(message)

        self.state = STATE_OPEN

        message_b = (json.dumps(message) + '\r\n').encode()
        logger.debug('Connected to Server. Send: {}'.format(message))

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer too large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # I dont know what were we supposed to do here
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'EXCHANGE': # Process rest of the handshake
            
            # Load server public key 
            received_public_key = load_pem_public_key(
                                    base64.b64decode(message['value'].encode()),
                                    backend=default_backend()
                                )

            # Generate shared_key 
            shared_key = self.private_key.exchange(received_public_key)

            # Generate derived_key: this is our shared secret.
            self.derived_key = HKDF(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=None,
                                    info=b'handshake data',
                                    backend=default_backend()
                                ).derive(shared_key)

            # Update state
            self.state = STATE_OPEN

            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)                

                message['data'] = base64.b64encode(data).decode()

                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """

        if message['type'] != 'ALGORITHMS' and self.state == STATE_OPEN:

            secure = {}
            payload, iv = encrypt(self.cipher, self.mode, json.dumps(message).encode(), self.derived_key)
            
            secure['payload'] = base64.b64encode(payload).decode()
            secure['iv'] = base64.b64encode(iv).decode()
            secure['type'] = 'SECURE_X'
            secure['hash'] = sintese(self.sintese, json.dumps(message).encode() + self.derived_key)
            message = secure

        else:

            self.state = STATE_HANDSHAKE

        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()