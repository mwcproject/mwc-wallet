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
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_native_certs::load_native_certs;
use serde::Serialize;
use serde_json::Value;
use std::convert::TryFrom;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

enum StreamReader {
	SSLReader(Option<BufReader<StreamOwned<ClientConnection, TcpStream>>>),
	PlainReader(Option<BufReader<TcpStream>>),
}

pub struct LineStream {
	reader: StreamReader,
	connected: bool,
}

impl LineStream {
	pub fn new(address: String) -> Result<Self, Error> {
		match Self::create_as_ssl(&address) {
			Ok(s) => Ok(s),
			Err(_) => return Self::create_as_plain(&address),
		}
	}

	fn create_tcp_stream(address: &String) -> Result<TcpStream, Error> {
		let address = address
			.to_socket_addrs()?
			.next()
			.ok_or(Error::Generic("Unable to parse address".into()))?;

		let timeout = Duration::from_secs(10);
		let stream = TcpStream::connect_timeout(&address, timeout)?;
		stream.set_read_timeout(Some(timeout))?;
		stream.set_write_timeout(Some(timeout))?;
		Ok(stream)
	}

	// If SSL failed, we can't reuse the tcp connection for the plain because the RPC feed is broken
	fn create_as_ssl(address: &String) -> Result<Self, Error> {
		// Trying to use SSL, in case of failure, will use plain connection
		let host: Vec<&str> = address.split(':').collect();
		let host = host[0];

		let mut root_store = RootCertStore::empty();
		let certs = load_native_certs().map_err(|e| {
			Error::ElectrumNodeClient(format!("Unable to load native certs, {}", e))
		})?;
		for cert in certs {
			let der = CertificateDer::from(cert.0);
			root_store.add(der).map_err(|e| {
				Error::ElectrumNodeClient(format!("Unable to add native cert, {}", e))
			})?;
		}
		let config = ClientConfig::builder()
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
		let tls_stream = StreamOwned::new(connection, stream);

		Ok(Self {
			reader: StreamReader::SSLReader(Some(BufReader::new(tls_stream))),
			connected: true,
		})
	}

	// If SSL failed, we can't reuse the tcp connection for the plain because the RPC feed is broken
	fn create_as_plain(address: &String) -> Result<Self, Error> {
		let stream = Self::create_tcp_stream(address)?;
		Ok(Self {
			reader: StreamReader::PlainReader(Some(BufReader::new(stream.try_clone()?))),
			connected: true,
		})
	}

	pub fn is_connected(&self) -> bool {
		self.connected
	}

	pub fn read_line(&mut self) -> Result<String, Error> {
		let mut line = String::new();

		let read_res = match &mut self.reader {
			StreamReader::SSLReader(stream) => match stream {
				Some(reader) => reader.read_line(&mut line),
				None => Ok(0),
			},
			StreamReader::PlainReader(stream) => match stream {
				Some(reader) => reader.read_line(&mut line),
				None => Ok(0),
			},
		};

		match read_res {
			Err(e) => {
				self.connected = false;
				return Err(e.into());
			}
			Ok(c) if c == 0 => {
				self.connected = false;
				return Err(Error::Generic("Connection closed".into()));
			}
			Ok(_) => {}
		}

		Ok(line)
	}

	pub fn write_line(&mut self, mut line: String) -> Result<(), Error> {
		line.push_str("\n");
		let bytes = line.into_bytes();

		// Reader must be non empty. We borrow the stream to write some data.
		// It is fine for RPC. If there are some non read lines - they will be lost.
		let res = match &mut self.reader {
			StreamReader::SSLReader(reader) => {
				let mut stream = reader
					.take()
					.ok_or(crate::swap::error::Error::Generic(
						"Reader is not set".into(),
					))?
					.into_inner();
				let res = stream.write_all(&bytes);
				reader.replace(BufReader::new(stream));
				res
			}
			StreamReader::PlainReader(reader) => {
				let mut stream = reader
					.take()
					.ok_or(crate::swap::error::Error::Generic(
						"Reader is not set".into(),
					))?
					.into_inner();
				let res = stream.write_all(&bytes);
				reader.replace(BufReader::new(stream));
				res
			}
		};
		res?;
		Ok(())
	}
}

pub struct RpcClient {
	inner: LineStream,
}

impl RpcClient {
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
#[serde(untagged)]
pub enum RpcResponse {
	ResponseErr(RpcResponseErr),
	ResponseOk(RpcResponseOk),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponseOk {
	pub id: Option<String>,
	pub result: Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponseErr {
	pub id: Option<String>,
	pub error: Value,
}
