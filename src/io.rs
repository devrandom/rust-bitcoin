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
pub use bare_io::*;

#[cfg(feature = "std")]
pub use std::io::*;

#[cfg(feature = "no-std")]
/// A simple Write-like trait to be used for consensus encoding in a no_std environment
// This eliminates the need to change the bitcoin_hashes crate, and can be removed
// if that crate adds bare-io support
pub mod encode {
	use io;
	use Vec;

	/// A simplified Write trait for no_std consensus encoding
	pub trait EncodingWrite {
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
	impl<W: EncodingWrite> EncodingWrite for &mut W {
		fn flush(&mut self) -> io::Result<()> {
			(*self).flush()
		}

		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			(*self).write(buf)
		}
	}

	impl EncodingWrite for Vec<u8> {
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

		#[inline]
		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}
}
