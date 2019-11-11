import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
from encrypt_decrypt_funcs import *
from cryptography.hazmat.primitives.serialization import load_pem_parameters, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE= 3

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''

		## Diffie-Hellman
		self.parameters = ''
		self.private_key = ''
		self.public_key = ''
		self.derived_key = ''

		## Cipher-suite
		self.cipher = ''
		self.mode = ''
		self.sintese = ''


	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
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
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return



		mtype = message.get('type', "").upper()

		if mtype == 'SECURE_X':
			old_hash = message['hash']
			message = self.process_payload(message['iv'], message['payload'])
			message = json.loads(message)
			
			hashed_msg = sintese(self.sintese, json.dumps(message).encode())
			if hashed_msg != old_hash:
				print("Error decoding message")
				# close connection
				self.transport.close()

		mtype = message.get('type', "").upper()

		if mtype == 'OPEN':
			ret = self.process_open(message)
		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)
		elif mtype == 'ALGORITHMS':
			ret = self.process_algorithms(message)
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])



		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True


	def process_algorithms(self, message: str) -> bool:
		"""
		Processes a ALGORITHMS message from the client
		This message should contain the list of algorithms to be used

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Algorithm List: {}".format(message))

		try:
			data = message.get('alg_list', None)
			if data is None:
				logger.warning("Invalid message. No data found")
				return False

			algList= message['alg_list']
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		algs=algList.split(';')
		logger.debug(algs)

		if algs[0]!="DH" or algs[1] not in ("AES-128","3DES") or algs[2] not in ("CBC","GCM","ECB") or algs[3] not in ("SHA-256","SHA-512"):
			logger.error('Unsupported algorithm, shutting down connection')
			self.transport.close()
			return False

		self.cipher = algs[1]
		self.mode = algs[2]
		self.sintese = algs[3]

		self.parameters = load_pem_parameters(base64.b64decode(message['params'].encode()), backend=default_backend())
		self.private_key = self.parameters.generate_private_key()
		self.public_key = self.private_key.public_key()

		received_public_key = load_pem_public_key(base64.b64decode(message['public_key'].encode()), backend=default_backend())

		shared_key = self.private_key.exchange(received_public_key)
		self.derived_key = HKDF(
								algorithm=hashes.SHA256(),
								length=32,
								salt=None,
								info=b'handshake data',
								backend=default_backend()
							).derive(shared_key)


		sendable_key = base64.b64encode(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).decode()

		#
		self._send({'type': 'EXCHANGE', 'value' : sendable_key})


		return True


	def process_payload(self, iv, payload: str) -> bool:

		# Converting back to binary
		real_iv = base64.b64decode(iv.encode())
		real_payload = base64.b64decode(payload.encode())

		return decrypt(self.cipher, self.mode, real_payload, real_iv, self.derived_key).decode()


	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		return True


	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)


def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


