// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
//! no_std polyfill 

#[cfg(feature = "no-std")]
pub use self::nano_io::*;

#[cfg(feature = "std")]
pub use std::io::*;

#[allow(missing_docs)]
#[cfg(feature = "no-std")]
/// A simple IO implementation for no_std
pub mod nano_io {
	use io;
	use Vec;
	use core::fmt::{Display, Debug};
	use alloc::boxed::Box;
	use String;
	use core::{cmp, fmt};

	pub struct Error {
		repr: Repr,
	}

	impl Error {
		pub fn new<E>(kind: ErrorKind, error: E) -> Error
			where
				E: Into<Box<dyn CustomError + Send + Sync>>,
		{
			Self::_new(kind, error.into())
		}

		fn _new(kind: ErrorKind, error: Box<dyn CustomError + Send + Sync>) -> Error {
			Error { repr: Repr::Custom(Box::new(Custom { kind, error })) }
		}

		fn kind(&self) -> ErrorKind {
			match self.repr {
				Repr::Custom(ref c) => c.kind,
				Repr::Simple(kind) => kind,
			}
		}
	}

	impl fmt::Debug for Error {
		fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
			fmt::Debug::fmt(&self.repr, f)
		}
	}

	impl fmt::Display for Error {
		fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
			match self.repr {
				Repr::Custom(ref c) => ::core::fmt::Display::fmt(&c.error, fmt),
				Repr::Simple(kind) => write!(fmt, "{}", kind.as_str()),
			}
		}
	}

	impl From<String> for Box<dyn CustomError + Send + Sync> {
		#[inline]
		fn from(err: String) -> Box<dyn CustomError + Send + Sync> {
			struct StringError(String);

			impl CustomError for StringError {
				#[allow(deprecated)]
				fn description(&self) -> &str {
					&self.0
				}
			}

			impl Display for StringError {
				fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
					Display::fmt(&self.0, f)
				}
			}

			impl Debug for StringError {
				fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
					Debug::fmt(&self.0, f)
				}
			}

			Box::new(StringError(err))
		}
	}

	impl<'a> From<&str> for Box<dyn CustomError + Send + Sync + 'a> {
		#[inline]
		fn from(err: &str) -> Box<dyn CustomError + Send + Sync + 'a> {
			From::from(String::from(err))
		}
	}

	pub trait CustomError: Display + Debug {
		fn description(&self) -> &str;
	}

	#[derive(Debug)]
	struct Custom {
		kind: ErrorKind,
		error: Box<dyn CustomError + Send + Sync>,
	}

	enum Repr {
		Simple(ErrorKind),
		Custom(Box<Custom>),
	}

	impl fmt::Debug for Repr {
		fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
			match *self {
				Repr::Custom(ref c) => fmt::Debug::fmt(&c, fmt),
				Repr::Simple(kind) => fmt.debug_tuple("Kind").field(&kind).finish(),
			}
		}
	}

	#[derive(Debug, Copy, Clone, PartialEq)]
	pub enum ErrorKind {
		Interrupted,
		InvalidInput,
		InvalidData,
		Other,
		WriteZero,
		UnexpectedEof,
	}

	impl ErrorKind {
		pub(crate) fn as_str(&self) -> &'static str {
			match *self {
				ErrorKind::Interrupted => "interrupted",
				ErrorKind::InvalidInput => "invalid input",
				ErrorKind::InvalidData => "invalid data",
				ErrorKind::Other => "other",
				ErrorKind::UnexpectedEof => "unexpected EOF",
				ErrorKind::WriteZero => "write zero",
			}
		}
	}

	impl From<ErrorKind> for Error {
		#[inline]
		fn from(kind: ErrorKind) -> Error {
			Error { repr: Repr::Simple(kind) }
		}
	}

	pub type Result<T> = ::core::result::Result<T, Error>;

	/// A simplified Write trait for no_std consensus encoding
	pub trait Write {
		/// x
		fn flush(&mut self) -> io::Result<()>;
		/// x
		fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
		/// x
		fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
			while !buf.is_empty() {
				match self.write(buf) {
					Ok(0) => {
						return Err(io::Error::new(
							io::ErrorKind::WriteZero,
							"failed to write whole buffer",
						));
					}
					Ok(n) => buf = &buf[n..],
					Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
					Err(e) => return Err(e),
				}
			}
			Ok(())
		}
	}

	// FIXME(devrandom) why isn't the compiler doing this automatically now?
	impl<W: Write> Write for &mut W {
		fn flush(&mut self) -> io::Result<()> {
			(*self).flush()
		}

		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			(*self).write(buf)
		}
	}

	impl Read for &[u8] {
		#[inline]
		fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
			let amt = cmp::min(buf.len(), self.len());
			let (a, b) = self.split_at(amt);

			// First check if the amount of bytes we want to read is small:
			// `copy_from_slice` will generally expand to a call to `memcpy`, and
			// for a single byte the overhead is significant.
			if amt == 1 {
				buf[0] = a[0];
			} else {
				buf[..amt].copy_from_slice(a);
			}

			*self = b;
			Ok(amt)
		}

		#[inline]
		fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
			if buf.len() > self.len() {
				return Err(Error::new(ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
			}
			let (a, b) = self.split_at(buf.len());

			// First check if the amount of bytes we want to read is small:
			// `copy_from_slice` will generally expand to a call to `memcpy`, and
			// for a single byte the overhead is significant.
			if buf.len() == 1 {
				buf[0] = a[0];
			} else {
				buf.copy_from_slice(a);
			}

			*self = b;
			Ok(())
		}
	}

	impl Write for Vec<u8> {
		#[inline]
		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}

		#[inline]
		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			self.extend_from_slice(buf);
			Ok(buf.len())
		}

		#[inline]
		fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
			self.extend_from_slice(buf);
			Ok(())
		}
	}

	pub struct Take<T> {
		inner: T,
		limit: u64,
	}

	pub trait Read {
		fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
		fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
			while !buf.is_empty() {
				match self.read(buf) {
					Ok(0) => break,
					Ok(n) => {
						let tmp = buf;
						buf = &mut tmp[n..];
					}
					Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
					Err(e) => return Err(e),
				}
			}
			if !buf.is_empty() {
				Err(Error::new(ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
			} else {
				Ok(())
			}
		}
		fn take(self, limit: u64) -> Take<Self>
			where
				Self: Sized,
		{
			Take { inner: self, limit }
		}
	}

	impl<T: Read> Read for Take<T> {
		fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
			// Don't call into inner reader at all at EOF because it may still block
			if self.limit == 0 {
				return Ok(0);
			}

			let max = cmp::min(buf.len() as u64, self.limit) as usize;
			let n = self.inner.read(&mut buf[..max])?;
			self.limit -= n as u64;
			Ok(n)
		}
	}

	pub struct Cursor<T> {
		inner: T,
		pos: u64,
	}

	impl<T> Cursor<T> {
		pub fn new(inner: T) -> Cursor<T> {
			Cursor { pos: 0, inner }
		}

		pub fn position(&self) -> u64 { self.pos }
	}


	impl<T> Read for Cursor<T>
		where
			T: AsRef<[u8]>,
	{
		fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
			let n = Read::read(&mut self.fill_buf()?, buf)?;
			self.pos += n as u64;
			Ok(n)
		}

		fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
			let n = buf.len();
			Read::read_exact(&mut self.fill_buf()?, buf)?;
			self.pos += n as u64;
			Ok(())
		}
	}

	impl<R: Read> Read for &mut R {
		fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
			(*self).read(buf)
		}
	}

	pub trait BufRead: Read {
		fn fill_buf(&mut self) -> Result<&[u8]>;
		fn consume(&mut self, amt: usize);
	}

	impl<T> BufRead for Cursor<T>
		where
			T: AsRef<[u8]>,
	{
		fn fill_buf(&mut self) -> io::Result<&[u8]> {
			let amt = cmp::min(self.pos, self.inner.as_ref().len() as u64);
			Ok(&self.inner.as_ref()[(amt as usize)..])
		}
		fn consume(&mut self, amt: usize) {
			self.pos += amt as u64;
		}
	}

}
