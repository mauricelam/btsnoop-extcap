use std::io::Read;

pub trait ReadExt: Read {
    /// Reads the exact number of bytes, like `read_exact`, but returns `None` if it gets EOF at
    /// the start of the read. In other words, this is the "all or nothing" version of `read`.
    fn try_read_exact<const N: usize>(&mut self) -> std::io::Result<Option<[u8; N]>> {
        let mut buf = [0_u8; N];
        let mut count = 0_usize;
        while count < N {
            let read_bytes = self.read(&mut buf[count..])?;
            if read_bytes == 0 {
                if count == 0 {
                    return Ok(None);
                } else {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
            }
            count += read_bytes;
        }
        Ok(Some(buf))
    }
}

impl<R: ?Sized + Read> ReadExt for R {}

#[cfg(test)]
mod test {
    use super::ReadExt;

    #[test]
    fn try_read_exact_success() {
        let bytes = b"test";
        let read_bytes = (&mut &bytes[..]).try_read_exact::<4>().unwrap();
        assert_eq!(Some(bytes), read_bytes.as_ref());
    }

    #[test]
    fn try_read_exact_long_success() {
        let bytes = b"testing long string";
        let mut slice = &bytes[..];
        assert_eq!(
            Some(b"test"),
            (&mut slice).try_read_exact::<4>().unwrap().as_ref()
        );
        assert_eq!(
            Some(b"ing "),
            (&mut slice).try_read_exact::<4>().unwrap().as_ref()
        );
    }

    #[test]
    fn try_read_exact_none() {
        let bytes = b"";
        let read_bytes = (&mut &bytes[..]).try_read_exact::<4>().unwrap();
        assert_eq!(None, read_bytes);
    }

    #[test]
    fn try_read_exact_unexpected_eof() {
        let bytes = b"tt";
        let read_bytes = (&mut &bytes[..]).try_read_exact::<4>();
        assert_eq!(
            read_bytes.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
