//The following is support mqs usage in mwc713
use crate::error::{Error, ErrorKind};
use grin_wallet_libwallet::swap::message::Message;
use grin_wallet_libwallet::Slate;
use std::sync::mpsc::Sender;
use url::Url; //only for the Address::parse

use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use regex::Regex;
use std::fmt::{self, Debug, Display};

const DEFAULT_MWCMQS_DOMAIN: &str = "mqs.mwc.mw";
pub const DEFAULT_MWCMQS_PORT: u16 = 443;

const ADDRESS_REGEX: &str = r"^((?P<address_type>mwcmq|mwcmqs|https|http)://).+$";

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

pub trait Publisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error>;
	fn encrypt_slate(&self, slate: &Slate, to: &dyn Address) -> Result<String, Error>;
	fn decrypt_slate(
		&self,
		from: String,
		mapmessage: String,
		signature: String,
		source_address: &ProvableAddress,
	) -> Result<String, Error>;
	fn post_take(&self, message: &Message, to: &dyn Address) -> Result<(), Error>;
	// Address of this publisher (from address)
	fn get_publisher_address(&self) -> Result<Box<dyn Address>, Error>;
}

pub trait Subscriber {
	fn start(&mut self) -> Result<(), Error>;
	fn stop(&mut self) -> bool;
	fn is_running(&self) -> bool;

	fn set_notification_channels(&self, slate_id: &uuid::Uuid, slate_send_channel: Sender<Slate>);
	fn reset_notification_channels(&self, slate_id: &uuid::Uuid);
}

pub trait SubscriptionHandler: Send {
	fn on_open(&self);
	fn on_slate(&self, from: &dyn Address, slate: &mut Slate);
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);
	// process swap message and return the message to respond
	fn on_swap_message(&self, swap: Message) -> Option<Message>;

	fn set_notification_channels(&self, slate_id: &uuid::Uuid, slate_send_channel: Sender<Slate>);
	fn reset_notification_channels(&self, slate_id: &uuid::Uuid);
}

//The following is support mqs usage in mwc713

pub trait Address: Debug + Display {
	fn from_str(s: &str) -> Result<Self, Error>
	where
		Self: Sized;
	fn address_type(&self) -> AddressType;
	fn get_stripped(&self) -> String;
	fn get_full_name(&self) -> String;
}

#[derive(Debug, PartialEq)]
pub enum AddressType {
	MWCMQS,
	Https,
}

#[derive(Clone, Debug)]
pub struct MWCMQSAddress {
	pub address: ProvableAddress,
	pub domain: String,
	pub port: u16,
}

const MWCMQ_ADDRESS_REGEX: &str = r"^(mwcmqs://)?(?P<public_key>[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{52})(@(?P<domain>[a-zA-Z0-9\.]+)(:(?P<port>[0-9]*))?)?$";

impl MWCMQSAddress {
	pub fn new(address: ProvableAddress, domain: Option<String>, port: Option<u16>) -> Self {
		Self {
			address,
			domain: domain.unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
			port: port.unwrap_or(DEFAULT_MWCMQS_PORT),
		}
	}
}

impl Display for MWCMQSAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "mwcmqs://{}", self.address.public_key)?;
		if self.domain != DEFAULT_MWCMQS_DOMAIN || self.port != DEFAULT_MWCMQS_PORT {
			write!(f, "@{}", self.domain)?;
			if self.port != DEFAULT_MWCMQS_PORT {
				write!(f, ":{}", self.port)?;
			}
		}
		Ok(())
	}
}

impl Address for MWCMQSAddress {
	/// Extract the address plus additional data
	fn from_str(s: &str) -> Result<Self, Error> {
		let re = Regex::new(MWCMQ_ADDRESS_REGEX).unwrap();
		let captures = re.captures(s);
		if captures.is_none() {
			Err(ErrorKind::MqsGenericError(format!(
				"Unable to parse MWC address {}",
				s
			)))?;
		}

		let captures = captures.unwrap();
		let public_key = captures
			.name("public_key")
			.ok_or(ErrorKind::MqsGenericError(format!(
				"Unable to parse MWC MQS address {}, public key part is not found",
				s
			)))?
			.as_str()
			.to_string();

		let domain = captures.name("domain").map(|m| m.as_str().to_string());
		let port = match captures.name("port") {
			Some(m) => Some(u16::from_str_radix(m.as_str(), 10).map_err(|_| {
				ErrorKind::MqsGenericError(format!("Unable to parse MWC MQS port value"))
			})?),
			None => None,
		};

		Ok(MWCMQSAddress::new(
			ProvableAddress::from_str(&public_key).map_err(|e| {
				ErrorKind::MqsGenericError(format!("Invalid MQS address {}, {}", s, e))
			})?,
			domain,
			port,
		))
	}

	fn get_stripped(&self) -> String {
		format!("{}", self)[9..].to_string()
	}

	fn get_full_name(&self) -> String {
		"mwcmqs://".to_string() + &self.get_stripped()
	}

	fn address_type(&self) -> AddressType {
		AddressType::MWCMQS
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpsAddress {
	pub uri: String,
}

impl Address for HttpsAddress {
	fn from_str(s: &str) -> Result<Self, Error> {
		Url::parse(s).map_err(|_| ErrorKind::HttpsAddressParsingError(s.to_string()))?;

		Ok(Self { uri: s.to_string() })
	}

	fn address_type(&self) -> AddressType {
		AddressType::Https
	}

	fn get_stripped(&self) -> String {
		self.uri.clone()
	}

	fn get_full_name(&self) -> String {
		self.get_stripped()
	}
}

impl Display for HttpsAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.uri)?;
		Ok(())
	}
}

impl dyn Address {
	pub fn parse(address: &str) -> Result<Box<dyn Address>, Error> {
		let re = Regex::new(ADDRESS_REGEX).map_err(|e| {
			ErrorKind::AddressGenericError(format!("Unable to construct address parser, {}", e))
		})?;
		let captures = re.captures(address);
		if captures.is_none() {
			return Ok(Box::new(MWCMQSAddress::from_str(address)?));
		}

		let captures = captures.unwrap();
		let address_type = captures.name("address_type").unwrap().as_str().to_string();
		let address: Box<dyn Address> = match address_type.as_ref() {
			"mwcmqs" => Box::new(MWCMQSAddress::from_str(address)?),
			"https" => Box::new(HttpsAddress::from_str(address)?),
			"http" => Box::new(HttpsAddress::from_str(address)?),
			x => Err(ErrorKind::UnknownAddressType(x.to_string()))?,
		};
		Ok(address)
	}
}
