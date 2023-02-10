use tokio::io::{AsyncRead, AsyncReadExt};

/// Reads the exact number of bytes, like `read_exact`, but returns `None` if it gets EOF at
/// the start of the read. In other words, this is the "all or nothing" version of `read`.
pub async fn try_read_exact<R: AsyncRead + Unpin, const N: usize>(
    read: &mut R,
) -> std::io::Result<Option<[u8; N]>> {
    let mut buf = [0_u8; N];
    let mut count = 0_usize;
    while count < N {
        let read_bytes = read.read(&mut buf[count..]).await?;
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

#[cfg(test)]
mod test {
    use super::try_read_exact;

    #[tokio::test]
    async fn try_read_exact_success() {
        let bytes = b"test";
        let read_bytes = try_read_exact::<_, 4>(&mut &bytes[..]).await.unwrap();
        assert_eq!(Some(bytes), read_bytes.as_ref());
    }

    #[tokio::test]
    async fn try_read_exact_long_success() {
        let bytes = b"testing long string";
        let mut slice = &bytes[..];
        assert_eq!(
            Some(b"test"),
            try_read_exact::<_, 4>(&mut slice).await.unwrap().as_ref()
        );
        assert_eq!(
            Some(b"ing "),
            try_read_exact::<_, 4>(&mut slice).await.unwrap().as_ref()
        );
    }

    #[tokio::test]
    async fn try_read_exact_none() {
        let bytes = b"";
        let read_bytes = try_read_exact::<_, 4>(&mut &bytes[..]).await.unwrap();
        assert_eq!(None, read_bytes);
    }

    #[tokio::test]
    async fn try_read_exact_unexpected_eof() {
        let bytes = b"tt";
        let read_bytes = try_read_exact::<_, 4>(&mut &bytes[..]).await;
        assert_eq!(
            read_bytes.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
