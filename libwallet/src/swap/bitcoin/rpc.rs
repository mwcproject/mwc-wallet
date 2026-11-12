// Copyright 2019 The vault713 Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::swap::Error;
use mwc_wallet_util::mwc_crates::rustls::crypto::ring;
use mwc_wallet_util::mwc_crates::rustls::pki_types::{CertificateDer, ServerName};
use mwc_wallet_util::mwc_crates::rustls::{
	ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use mwc_wallet_util::mwc_crates::rustls_native_certs::load_native_certs;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::serde_json::Value;
use std::convert::TryFrom;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

// Enforce one deadline below TLS, whose handshake and record reads may perform
// many socket operations without returning to LineStream.
struct DeadlineTcpStream {
	inner: TcpStream,
	request_started: Instant,
	timeout: Duration,
}

impl DeadlineTcpStream {
	fn new(inner: TcpStream, timeout: Duration) -> Self {
		Self {
			inner,
			request_started: Instant::now(),
			timeout,
		}
	}

	fn start_request(&mut self) {
		self.request_started = Instant::now();
	}

	fn remaining(&self) -> io::Result<Duration> {
		self.timeout
			.checked_sub(self.request_started.elapsed())
			.filter(|remaining| !remaining.is_zero())
			.ok_or_else(|| {
				io::Error::new(io::ErrorKind::TimedOut, "Electrum RPC deadline exceeded")
			})
	}
}

impl Read for DeadlineTcpStream {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		self.inner.set_read_timeout(Some(self.remaining()?))?;
		let result = self.inner.read(buf);
		self.remaining()?;
		result
	}
}

impl Write for DeadlineTcpStream {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.inner.set_write_timeout(Some(self.remaining()?))?;
		let result = self.inner.write(buf);
		self.remaining()?;
		result
	}

	fn flush(&mut self) -> io::Result<()> {
		self.remaining()?;
		self.inner.flush()
	}
}

enum StreamReader {
	SSLReader(Option<BufReader<StreamOwned<ClientConnection, DeadlineTcpStream>>>),
	PlainReader(Option<BufReader<DeadlineTcpStream>>),
}

pub struct LineStream {
	reader: StreamReader,
	connected: bool,
}

impl LineStream {
	pub fn new(address: String) -> Result<Self, Error> {
		match Self::create_as_ssl(&address) {
			Ok(s) => Ok(s),
			Err(tls_error) => Self::create_as_plain(&address).map_err(|plain_error| {
				Error::ElectrumNodeClient(format!(
					"Unable to connect to {} using TLS ({}) or plaintext ({})",
					address, tls_error, plain_error
				))
			}),
		}
	}

	fn create_tcp_stream(address: &String) -> Result<TcpStream, Error> {
		// RPC_TIMEOUT bounds TCP connection establishment only. Hostname lookup
		// uses the blocking system resolver and may take longer, delaying fallback
		// to another node. This is an accepted availability tradeoff; a strict
		// lookup-plus-connect deadline is not required here. to_socket_addrs() has
		// no per-call timeout or cancellation, so enforcing such a deadline would
		// need managed background workers or a different resolver. That complexity
		// is not justified solely to make DNS share the TCP timeout.
		let address = address
			.to_socket_addrs()?
			.next()
			.ok_or(Error::Generic("Unable to parse address".into()))?;

		Ok(TcpStream::connect_timeout(&address, RPC_TIMEOUT)?)
	}

	// If SSL failed, we can't reuse the tcp connection for the plain because the RPC feed is broken
	fn create_as_ssl(address: &String) -> Result<Self, Error> {
		// Trying to use SSL, in case of failure, will use plain connection
		let host = address
			.rsplit_once(':')
			.map(|(host, _)| host.trim_matches(['[', ']']))
			.ok_or_else(|| Error::Generic(format!("Unable to parse address {}", address)))?;

		let mut root_store = RootCertStore::empty();
		let cert_result = load_native_certs();
		if !cert_result.errors.is_empty() {
			return Err(Error::ElectrumNodeClient(format!(
				"Unable to load all native certs: {:?}",
				cert_result.errors
			)));
		}
		for cert in cert_result.certs {
			root_store.add(CertificateDer::from(cert)).map_err(|e| {
				Error::ElectrumNodeClient(format!("Unable to add native cert, {}", e))
			})?;
		}
		let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
			.with_safe_default_protocol_versions()
			.map_err(|e| {
				Error::ElectrumNodeClient(format!(
					"Unable to configure TLS protocol versions, {}",
					e
				))
			})?
			.with_root_certificates(root_store)
			.with_no_client_auth();
		let server_name = match host.parse::<IpAddr>() {
			Ok(ip) => ServerName::IpAddress(ip.into()),
			Err(_) => ServerName::try_from(String::from(host)).map_err(|_| {
				Error::ElectrumNodeClient(format!("Unable to parse server name {}", host))
			})?,
		};

		let stream = Self::create_tcp_stream(address)?;
		let connection = ClientConnection::new(Arc::new(config), server_name).map_err(|e| {
			Error::ElectrumNodeClient(format!("Unable to create TLS connection, {}", e))
		})?;
		let mut tls_stream =
			StreamOwned::new(connection, DeadlineTcpStream::new(stream, RPC_TIMEOUT));
		// Rustls constructors defer the handshake. Complete it here so failures
		// reach new() while it can still open a fresh plaintext connection.
		while tls_stream.conn.is_handshaking() {
			tls_stream
				.conn
				.complete_io(&mut tls_stream.sock)
				.map_err(|e| {
					Error::ElectrumNodeClient(format!(
						"Unable to complete TLS handshake with {}, {}",
						address, e
					))
				})?;
		}
		tls_stream.sock.remaining()?;

		Ok(Self {
			reader: StreamReader::SSLReader(Some(BufReader::new(tls_stream))),
			connected: true,
		})
	}

	// If SSL failed, we can't reuse the tcp connection for the plain because the RPC feed is broken
	fn create_as_plain(address: &String) -> Result<Self, Error> {
		let stream = Self::create_tcp_stream(address)?;
		Ok(Self {
			reader: StreamReader::PlainReader(Some(BufReader::new(DeadlineTcpStream::new(
				stream,
				RPC_TIMEOUT,
			)))),
			connected: true,
		})
	}

	pub fn is_connected(&self) -> bool {
		self.connected
	}

	fn transport(&mut self) -> io::Result<&mut DeadlineTcpStream> {
		match &mut self.reader {
			StreamReader::SSLReader(Some(reader)) => Ok(&mut reader.get_mut().sock),
			StreamReader::PlainReader(Some(reader)) => Ok(reader.get_mut()),
			_ => Err(io::Error::new(
				io::ErrorKind::NotConnected,
				"Reader is not set",
			)),
		}
	}

	fn disconnect(&mut self) {
		self.connected = false;
		// Drop the socket and any buffered partial response immediately. The
		// Electrum client cache will reconnect on its next request.
		match &mut self.reader {
			StreamReader::SSLReader(reader) => *reader = None,
			StreamReader::PlainReader(reader) => *reader = None,
		}
	}

	pub fn read_line(&mut self) -> Result<String, Error> {
		let mut line = String::new();

		let read_res = (|| -> io::Result<usize> {
			// Reading the response shares the request's deadline, including time
			// spent writing and handshaking. Check even when data is buffered.
			self.transport()?.remaining()?;
			let count = match &mut self.reader {
				StreamReader::SSLReader(Some(reader)) => reader.read_line(&mut line),
				StreamReader::PlainReader(Some(reader)) => reader.read_line(&mut line),
				_ => Err(io::Error::new(
					io::ErrorKind::NotConnected,
					"Reader is not set",
				)),
			}?;
			self.transport()?.remaining()?;
			Ok(count)
		})();

		match read_res {
			Err(e) => {
				self.disconnect();
				return Err(e.into());
			}
			Ok(c) if c == 0 => {
				self.disconnect();
				return Err(Error::Generic("Connection closed".into()));
			}
			Ok(_) => {}
		}

		Ok(line)
	}

	pub fn write_line(&mut self, mut line: String) -> Result<(), Error> {
		line.push_str("\n");
		let bytes = line.into_bytes();

		let res = (|| -> io::Result<()> {
			self.transport()?.start_request();
			// Keep any buffered response bytes while writing to the underlying stream.
			let writer: &mut dyn Write = match &mut self.reader {
				StreamReader::SSLReader(Some(reader)) => reader.get_mut(),
				StreamReader::PlainReader(Some(reader)) => reader.get_mut(),
				_ => {
					return Err(io::Error::new(
						io::ErrorKind::NotConnected,
						"Reader is not set",
					));
				}
			};
			writer.write_all(&bytes)?;
			writer.flush()?;
			self.transport()?.remaining()?;
			Ok(())
		})()
		.map_err(Error::from);
		if res.is_err() {
			self.disconnect();
		}
		res
	}
}

pub struct RpcClient {
	inner: LineStream,
}

impl RpcClient {
	#[cfg(test)]
	pub(super) fn from_plain_stream(stream: TcpStream) -> Self {
		Self {
			inner: LineStream {
				reader: StreamReader::PlainReader(Some(BufReader::new(DeadlineTcpStream::new(
					stream,
					RPC_TIMEOUT,
				)))),
				connected: true,
			},
		}
	}

	pub fn new(address: String) -> Result<Self, Error> {
		let inner = LineStream::new(address.clone())
			.map_err(|e| Error::Rpc(format!("Unable connect to {}, {}", address, e)))?;
		Ok(Self { inner })
	}

	pub fn is_connected(&self) -> bool {
		self.inner.is_connected()
	}

	pub fn read(&mut self) -> Result<RpcResponse, Error> {
		let line = self
			.inner
			.read_line()
			.map_err(|e| Error::Rpc(format!("Unable to read line, {}", e)))?;
		let result: RpcResponse = serde_json::from_str(&line)
			.map_err(|e| Error::Rpc(format!("Unable to deserialize '{}', {}", line, e)))?;
		Ok(result)
	}

	pub fn write(&mut self, request: &RpcRequest) -> Result<(), Error> {
		let line = serde_json::to_string(request)
			.map_err(|e| Error::Rpc(format!("Unable to serialize, {}", e)))?;
		self.inner
			.write_line(line)
			.map_err(|e| Error::Rpc(format!("Unable to write line, {}", e)))?;
		Ok(())
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct RpcRequest {
	pub id: String,
	jsonrpc: String,
	method: String,
	params: Option<Value>,
}

impl RpcRequest {
	pub fn new<T: Serialize>(id: u32, method: &str, params: T) -> Result<Self, Error> {
		Ok(Self {
			id: format!("{}", id),
			jsonrpc: "2.0".into(),
			method: method.into(),
			params: Some(serde_json::to_value(params)?),
		})
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
#[serde(untagged)]
pub enum RpcResponse {
	ResponseErr(RpcResponseErr),
	ResponseOk(RpcResponseOk),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct RpcResponseOk {
	pub id: Option<String>,
	pub result: Value,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct RpcResponseErr {
	pub id: Option<String>,
	pub error: Value,
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::{Shutdown, TcpListener};
	use std::thread;

	fn socket_pair() -> (TcpStream, TcpStream) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
		let (peer, _) = listener.accept().unwrap();
		(socket, peer)
	}

	fn tls_line_stream(socket: TcpStream, timeout: Duration) -> LineStream {
		let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(RootCertStore::empty())
			.with_no_client_auth();
		let connection =
			ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
				.unwrap();
		LineStream {
			reader: StreamReader::SSLReader(Some(BufReader::new(StreamOwned::new(
				connection,
				DeadlineTcpStream::new(socket, timeout),
			)))),
			connected: true,
		}
	}

	fn trickle_bytes(mut peer: TcpStream, bytes: Vec<u8>) -> thread::JoinHandle<()> {
		thread::spawn(move || {
			for byte in bytes {
				if peer.write_all(&[byte]).is_err() {
					break;
				}
				thread::sleep(Duration::from_millis(20));
			}
		})
	}

	// A plaintext server rejects a TLS probe, then accepts version negotiation
	// and transaction broadcast on a fresh connection.
	#[test]
	fn tls_handshake_failure_falls_back_to_plaintext() {
		use crate::swap::bitcoin::{BtcNodeClient, ElectrumNodeClient};

		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap().to_string();
		let server = thread::spawn(move || {
			let (peer, _) = listener.accept().unwrap();
			peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
			let mut reader = BufReader::new(peer);
			// TLS can also fail before connecting if native certificates cannot load.
			if reader.fill_buf().unwrap().first() == Some(&0x16) {
				reader.get_mut().write_all(b"not a TLS server\n").unwrap();
				drop(reader);
				let (peer, _) = listener.accept().unwrap();
				peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
				reader = BufReader::new(peer);
			}
			for (method, result) in [
				("server.version", serde_json::json!(["test-server", "1.4"])),
				(
					"blockchain.transaction.broadcast",
					serde_json::json!("ab".repeat(32)),
				),
			] {
				let mut line = String::new();
				reader.read_line(&mut line).unwrap();
				let request: Value = serde_json::from_str(&line).unwrap();
				assert_eq!(request["method"], method);
				if method == "blockchain.transaction.broadcast" {
					assert_eq!(request["params"]["raw_tx"], "010203");
				}
				let response = serde_json::json!({"id": request["id"], "result": result});
				writeln!(reader.get_mut(), "{response}").unwrap();
				reader.get_mut().flush().unwrap();
			}
		});

		let mut node = ElectrumNodeClient::new(address, String::new());
		node.post_tx(vec![1, 2, 3]).unwrap();
		server.join().unwrap();
	}

	// Close the socket's write side, then issue a plaintext RPC request. Expect
	// the write error to propagate and the stream to be marked disconnected.
	#[test]
	fn failed_plain_write_disconnects() {
		let (socket, _peer) = socket_pair();
		socket.shutdown(Shutdown::Write).unwrap();
		let mut stream = LineStream {
			reader: StreamReader::PlainReader(Some(BufReader::new(DeadlineTcpStream::new(
				socket,
				RPC_TIMEOUT,
			)))),
			connected: true,
		};
		assert!(stream.write_line("request".into()).is_err());
		assert!(!stream.is_connected());
	}

	// Put TLS over a socket whose write side is closed, then issue a request.
	// A TLS write failure must invalidate the stream just like a plaintext failure.
	#[test]
	fn failed_tls_write_disconnects() {
		let (socket, _peer) = socket_pair();
		socket.shutdown(Shutdown::Write).unwrap();
		let mut stream = tls_line_stream(socket, RPC_TIMEOUT);
		assert!(stream.write_line("request".into()).is_err());
		assert!(!stream.is_connected());
	}

	// Attempt a write with no underlying reader in each transport variant.
	// Expect an error and a disconnected flag, including this early failure path.
	#[test]
	fn missing_writer_disconnects() {
		for reader in [
			StreamReader::PlainReader(None),
			StreamReader::SSLReader(None),
		] {
			let mut stream = LineStream {
				reader,
				connected: true,
			};
			assert!(stream.write_line("request".into()).is_err());
			assert!(!stream.is_connected());
		}
	}

	// Buffer a server response before sending another request. Expect the write
	// to preserve those unread bytes, send one newline-terminated request, and
	// leave the connection usable for reading the buffered response.
	#[test]
	fn successful_write_preserves_buffered_responses() {
		let (socket, mut peer) = socket_pair();
		socket
			.set_read_timeout(Some(Duration::from_secs(2)))
			.unwrap();
		peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
		let mut reader = BufReader::new(DeadlineTcpStream::new(socket, RPC_TIMEOUT));
		peer.write_all(b"response\n").unwrap();
		assert!(!reader.fill_buf().unwrap().is_empty());
		let mut stream = LineStream {
			reader: StreamReader::PlainReader(Some(reader)),
			connected: true,
		};
		// An idle connection gets a fresh budget when the next request starts.
		stream.transport().unwrap().request_started =
			Instant::now().checked_sub(RPC_TIMEOUT).unwrap();
		stream.write_line("request".into()).unwrap();
		assert!(stream.is_connected());
		assert_eq!(stream.read_line().unwrap(), "response\n");
		let mut request = String::new();
		BufReader::new(peer).read_line(&mut request).unwrap();
		assert_eq!(request, "request\n");
	}

	// Progress every 20 ms must not extend the whole-response budget. The error
	// must reach RpcClient's caller so the swap API can use its fallback.
	#[test]
	fn trickling_rpc_response_expires_and_disconnects() {
		let (socket, peer) = socket_pair();
		let mut client = RpcClient {
			inner: LineStream {
				reader: StreamReader::PlainReader(Some(BufReader::new(DeadlineTcpStream::new(
					socket,
					Duration::from_millis(200),
				)))),
				connected: true,
			},
		};
		let sender = trickle_bytes(peer, b"{\"id\":\"1\",\"result\":1234567890}\n".to_vec());
		let request = RpcRequest::new(1, "test", Vec::<String>::new()).unwrap();
		client.write(&request).unwrap();
		let started = Instant::now();
		let error = client.read().unwrap_err();
		assert!(matches!(error, Error::Rpc(_)));
		assert!(started.elapsed() < Duration::from_secs(2));
		assert!(!client.is_connected());
		assert!(matches!(
			client.inner.reader,
			StreamReader::PlainReader(None)
		));
		sender.join().unwrap();
	}

	// A partial TLS record does not yield application bytes. The deadline must
	// apply inside rustls, including the handshake triggered by a request write.
	#[test]
	fn trickling_tls_record_expires_during_read_and_write() {
		for during_write in [false, true] {
			let (socket, mut peer) = socket_pair();
			let mut stream = tls_line_stream(socket, Duration::from_millis(200));
			// Announce a 4096-byte handshake record, then trickle an incomplete body.
			peer.write_all(&[0x16, 0x03, 0x03, 0x10, 0x00]).unwrap();
			let sender = trickle_bytes(peer, vec![0; 50]);
			let started = Instant::now();
			let error = if during_write {
				stream.write_line("request".into()).unwrap_err()
			} else {
				stream.read_line().unwrap_err()
			};
			assert!(matches!(error, Error::IO(message) if
				message.contains("deadline") || message.contains("timed out") ||
				message.contains("temporarily unavailable")));
			assert!(started.elapsed() < Duration::from_secs(2));
			assert!(!stream.is_connected());
			assert!(matches!(stream.reader, StreamReader::SSLReader(None)));
			sender.join().unwrap();
		}
	}

	// Receiving a response must not restart the request deadline, even if its
	// complete line is already buffered and no socket read would be necessary.
	#[test]
	fn buffered_response_cannot_bypass_expired_request_deadline() {
		let (socket, mut peer) = socket_pair();
		let mut stream = LineStream {
			reader: StreamReader::PlainReader(Some(BufReader::new(DeadlineTcpStream::new(
				socket,
				RPC_TIMEOUT,
			)))),
			connected: true,
		};
		stream.write_line("request".into()).unwrap();
		peer.write_all(b"response\n").unwrap();
		if let StreamReader::PlainReader(Some(reader)) = &mut stream.reader {
			assert!(!reader.fill_buf().unwrap().is_empty());
		}
		stream.transport().unwrap().request_started =
			Instant::now().checked_sub(RPC_TIMEOUT).unwrap();
		assert!(stream.read_line().is_err());
		assert!(!stream.is_connected());
		assert!(matches!(stream.reader, StreamReader::PlainReader(None)));
	}
}
