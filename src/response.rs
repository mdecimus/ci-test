use std::borrow::Cow;

#[derive(Debug, Clone)]
pub enum Response {
    Message {
        code: u16,
        message: Cow<'static, str>,
    },
    Lhlo {
        local_host: String,
        remote_host: String,
        extensions: Vec<Extension>,
    },
}

#[derive(Debug, Clone)]
pub enum Extension {
    EightBitMime,
    BinaryMime,
    Size(u32),
    Dsn,
    Vrfy,
    Help,
    Pipelining,
    Chunking,
    SmtpUtf8,
    StartTls,
}

impl Response {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Response::Message { code, message } => format!("{} {}\r\n", code, message).into_bytes(),
            Response::Lhlo {
                local_host,
                remote_host,
                extensions,
            } => {
                let mut buf = Vec::with_capacity(
                    local_host.len() + remote_host.len() + extensions.len() * 20,
                );
                buf.extend_from_slice(b"250-");
                buf.extend_from_slice(local_host.as_bytes());
                buf.extend_from_slice(b" welcomes ");
                buf.extend_from_slice(remote_host.as_bytes());
                buf.extend_from_slice(b"\r\n");
                for (pos, extension) in extensions.iter().enumerate() {
                    if pos < extensions.len() - 1 {
                        buf.extend_from_slice(b"250-");
                    } else {
                        buf.extend_from_slice(b"250 ");
                    };
                    match extension {
                        Extension::EightBitMime => buf.extend_from_slice(b"8BITMIME"),
                        Extension::BinaryMime => buf.extend_from_slice(b"BINARYMIME"),
                        Extension::Size(size) => {
                            buf.extend_from_slice(b"SIZE ");
                            buf.extend_from_slice(size.to_string().as_bytes())
                        }
                        Extension::Dsn => buf.extend_from_slice(b"DSN"),
                        Extension::Vrfy => buf.extend_from_slice(b"VRFY"),
                        Extension::Help => buf.extend_from_slice(b"HELP"),
                        Extension::Pipelining => buf.extend_from_slice(b"PIPELINING"),
                        Extension::Chunking => buf.extend_from_slice(b"CHUNKING"),
                        Extension::SmtpUtf8 => buf.extend_from_slice(b"SMTPUTF8"),
                        Extension::StartTls => buf.extend_from_slice(b"STARTTLS"),
                    }
                    buf.extend_from_slice(b"\r\n");
                }

                buf
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Extension, Response};

    #[test]
    fn lmtp_response() {
        for (response, expected_text) in [
            (
                Response::Message {
                    code: 354,
                    message: "go ahead".into(),
                },
                "354 go ahead\r\n",
            ),
            (
                Response::Lhlo {
                    local_host: "foo.com".to_string(),
                    remote_host: "bar.com".to_string(),
                    extensions: vec![
                        Extension::EightBitMime,
                        Extension::BinaryMime,
                        Extension::Size(123),
                        Extension::Dsn,
                        Extension::Vrfy,
                        Extension::Help,
                        Extension::Pipelining,
                        Extension::Chunking,
                        Extension::SmtpUtf8,
                        Extension::StartTls,
                    ],
                },
                concat!(
                    "250-foo.com welcomes bar.com\r\n",
                    "250-8BITMIME\r\n",
                    "250-BINARYMIME\r\n",
                    "250-SIZE 123\r\n",
                    "250-DSN\r\n",
                    "250-VRFY\r\n",
                    "250-HELP\r\n",
                    "250-PIPELINING\r\n",
                    "250-CHUNKING\r\n",
                    "250-SMTPUTF8\r\n",
                    "250 STARTTLS\r\n"
                ),
            ),
        ] {
            assert_eq!(
                String::from_utf8(response.into_bytes()).unwrap(),
                expected_text
            );
        }
    }
}
