use crate::proto::{
    self, ReqId, SFTP_FIELD_ID_INDEX, SFTP_FIELD_LEN_INDEX, SFTP_FIELD_LEN_LENGTH,
    SFTP_FIELD_REQ_ID_INDEX, SFTP_FIELD_REQ_ID_LEN, SFTP_MINIMUM_PACKET_LEN,
    SftpNum, SftpPacket,
};

use sunset::error::TrapBug;
use sunset::sshwire;

use crate::sftperror::{SftpError, SftpResult};

use crate::sftphandler::SFTPBBQueue;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// SftpSource implements [`SSHSource`] and also extra functions to handle
/// some challenges related to long SFTP packets in constrained environments
#[derive(Default, Debug)]
pub struct SftpSource<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> SftpSource<'a> {
    /// Creates a new `SftpSource` with storage.
    ///
    /// Existing data in `buffer` is unused.
    /// `buffer` should have space for the packet, will panic
    /// if less than 9, the minimum packet size.
    pub fn empty(buffer: &'a mut [u8]) -> Self {
        // We assume a buffer can hold at least a min packet.
        assert!(buffer.len() >= SFTP_MINIMUM_PACKET_LEN);
        SftpSource { buffer, len: 0 }
    }

    /// Creates a `SftpSource` with content.
    ///
    /// Will panic on a short packet. Used for tests.
    #[cfg(test)]
    pub(crate) fn from_data(buffer: &'a mut [u8]) -> Self {
        assert!(buffer.len() >= SFTP_MINIMUM_PACKET_LEN);
        SftpSource { len: buffer.len(), buffer }
    }

    /// Helper for current packet data.
    fn data(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    /// Helper for spare buffer space.
    ///
    /// Returns None if too long.
    fn spare(&mut self, size: usize) -> Option<&mut [u8]> {
        let end = self.len.checked_add(size)?;
        self.buffer.get_mut(self.len..end)
    }

    /// Peeks the buffer for packet type [`SftpNum`]. This does not advance
    /// the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a
    /// `dec(s)` would fail
    pub(crate) fn peek_packet_type(&self) -> Option<SftpNum> {
        let data = self.data();
        if data.len() <= SFTP_FIELD_ID_INDEX {
            debug!(
                "Peek packet type failed: buffer len <= SFTP_FIELD_ID_INDEX ( {:?} <= {:?})",
                data.len(),
                SFTP_FIELD_ID_INDEX
            );
            None
        } else {
            Some(SftpNum::from(data[SFTP_FIELD_ID_INDEX]))
        }
    }

    /// Peeks the buffer for packet length field. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)`
    /// would fail
    pub(crate) fn peek_packet_len(&self) -> Option<usize> {
        let len = self.data().get(
            SFTP_FIELD_LEN_INDEX..SFTP_FIELD_LEN_INDEX + SFTP_FIELD_LEN_LENGTH,
        )?;

        let bytes: [u8; 4] = len.try_into().unwrap();
        Some(u32::from_be_bytes(bytes) as usize)
    }

    /// Peeks the packet in the source to obtain a total packet length, which
    /// considers the length of the length field itself. For the packet length field
    /// use [`peek_packet_len()`]
    ///
    ///  This does not advance the reading index
    pub(crate) fn peek_total_packet_len(&self) -> Option<usize> {
        self.peek_packet_len()?.checked_add(SFTP_FIELD_LEN_LENGTH)
    }

    /// Peeks the buffer for packet request id [`u32`]. This does not advance
    /// the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a
    /// `dec(s)` would fail
    pub fn peek_packet_req_id(&self) -> Option<ReqId> {
        let r = self.data().get(
            SFTP_FIELD_REQ_ID_INDEX..SFTP_FIELD_REQ_ID_INDEX + SFTP_FIELD_REQ_ID_LEN,
        )?;

        let bytes: [u8; 4] = r.try_into().unwrap();
        Some(ReqId(u32::from_be_bytes(bytes)))
    }

    /// Returns the number of bytes remaining in the packet.
    ///
    /// This is a lower bound, more reads may be required.
    /// `needed()` can be called again after reading in the data.
    fn needed(&self) -> usize {
        // All packets have length, type, req_id
        let l = SFTP_MINIMUM_PACKET_LEN.saturating_sub(self.len);
        if l > 0 {
            return l;
        }

        // OK unwrap, packet is at least SFTP_MINIMUM_PACKET_LEN
        let len = self.peek_total_packet_len().unwrap();
        if len < SFTP_MINIMUM_PACKET_LEN {
            // Finish and let the caller fail.
            return 0;
        }
        let ty = self.peek_packet_type().unwrap();

        debug_assert!(self.len <= len, "Can't fill longer than a packet");

        match ty {
            SftpNum::SSH_FXP_WRITE => {
                // `proto::Write` struct has a reduced length compared to the total
                // packet length, since it doesn't include actual write data.
                // The handle length is variable, so we need to peek at it.
                // (Sunset uses a fixed length, but we can't guarantee that from peers)

                // Skip past req_id
                let body = &self.data()[SFTP_MINIMUM_PACKET_LEN..];
                // Reduced total len
                let wlen = SFTP_MINIMUM_PACKET_LEN
                    + proto::Write::peek_len(body)
                        .unwrap_or(proto::Write::PEEK_NEEDED);
                debug_assert!(self.len <= wlen);
                wlen - self.len
            }
            SftpNum::Other(_) => {
                // Unknown packets will be skipped over, so just read the req_id
                // if included.
                let req_id_len = SFTP_FIELD_REQ_ID_INDEX + SFTP_FIELD_REQ_ID_LEN;
                req_id_len.min(len) - self.len
            }
            _ => {
                // Normal packet, need all remaining packet content.
                len - self.len
            }
        }
    }

    /// Discards input data to the end of packet length.
    ///
    /// Must be called with a valid packet length in the buffer.
    pub async fn drain<const B: usize>(
        &self,
        input: &SFTPBBQueue<B>,
    ) -> SftpResult<()> {
        let total_len = self.peek_total_packet_len().trap()?;
        let mut len = total_len.checked_sub(self.len).trap()?;

        let cons = input.stream_consumer();
        while len > 0 {
            let inp = cons.wait_read().await;
            let l = inp.len().min(len);
            inp.release(l);
            len -= l;
        }
        Ok(())
    }

    pub async fn fill<const B: usize>(
        &mut self,
        input: &SFTPBBQueue<B>,
    ) -> SftpDecoded<'_> {
        let cons = input.stream_consumer();
        loop {
            let l = self.needed();
            if l == 0 {
                break;
            }

            // Check for space to read into
            let Some(dest) = self.spare(l) else {
                let Some(req_id) = self.peek_packet_req_id() else {
                    debug!("Short packet, no req_id");
                    return SftpDecoded::FillError {
                        error: SftpError::MalformedPacket,
                    };
                };

                // OK unwrap, packet len is before req_id so must succeed.
                let total_len = self.peek_total_packet_len().unwrap();

                // Drain remainder of packet, ready for the next packet.
                if let Err(error) = self.drain(input).await {
                    trace!("Packet drain failed");
                    return SftpDecoded::FillError { error };
                }

                warn!("Packet buffer full, len {}", total_len);
                if total_len > proto::SFTP_MAXIMUM_PACKET_LEN {
                    debug!("Packet too long");
                    return SftpDecoded::BadMessage { req_id };
                } else {
                    return SftpDecoded::Failure { req_id };
                }
            };

            // Fill dest from input bbqueue
            let mut b = 0;
            while b < dest.len() {
                let inp = cons.wait_read().await;
                let l = (dest.len() - b).min(inp.len());
                dest[b..][..l].copy_from_slice(&inp[..l]);
                inp.release(l);
                b += l;
            }

            self.len += dest.len();
        }

        let res = self.decode();

        // Unknown packets need to drain to end of packet.
        if let SftpDecoded::UnknownPacket { .. } = res {
            if let Err(error) = self.drain(input).await {
                return SftpDecoded::FillError { error };
            }
        }

        res
    }

    pub fn decode(&self) -> SftpDecoded<'_> {
        let Some(req_id) = self.peek_packet_req_id() else {
            // Packet is shorter than minimum.
            return SftpDecoded::FillError {
                error: sunset::Error::build_bug().into(),
            };
        };

        // Skip the length prefix
        let pkt_data = &self.buffer[..self.len][SFTP_FIELD_ID_INDEX..];

        match sshwire::read_ssh::<SftpPacket>(pkt_data, None) {
            Ok((pkt, declen)) => {
                // Check that the entire packet is consumed
                // TODO Attrs extensions are not yet handled.

                let expect_len = match &pkt {
                    SftpPacket::Write(_req_id, w) => {
                        // Write struct needs special handling
                        // since it doesn't cover the data at the end.

                        // OK unwrap, length checked above.
                        let full_len = self.peek_packet_len().unwrap();
                        let Some(l) = full_len.checked_sub(w.data_len as usize)
                        else {
                            trace!("Bad write len {:?}", pkt);
                            return SftpDecoded::BadMessage { req_id };
                        };
                        l
                    }
                    _ => pkt_data.len(),
                };

                if declen == expect_len {
                    SftpDecoded::Packet(pkt)
                } else {
                    debug!(
                        "Short packet req {:?}, {}/{}",
                        req_id, declen, expect_len
                    );
                    trace!("Short {:?}", pkt);
                    SftpDecoded::BadMessage { req_id }
                }
            }
            Err(sunset::Error::UnknownPacket { number }) => {
                SftpDecoded::UnknownPacket { req_id, number }
            }
            Err(error) => {
                debug!("Error decoding packet: {:?} req {:?}", error, req_id);
                SftpDecoded::BadMessage { req_id }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum SftpDecoded<'a> {
    /// A known packet was parsed.
    Packet(SftpPacket<'a>),
    /// Should send a `SSH_FX_OP_UNSUPPORTED` response.
    UnknownPacket {
        req_id: ReqId,
        #[allow(unused)]
        /// Packet type
        number: u8,
    },
    /// The received packet was incorrectly formatted.
    ///
    /// Should send a `SSH_FX_BAD_MESSAGE` response.
    BadMessage { req_id: ReqId },
    /// An error occurred decoding the packet.
    ///
    /// This may occur for correct packets if Sunset does not
    /// handle them, for example hitting length limits.
    ///
    /// Should send a `SSH_FX_FAILURE` response.
    Failure { req_id: ReqId },
    /// An unrecoverable error occurred in the input.
    ///
    /// The connection must close.
    FillError { error: SftpError },
}

#[cfg(test)]
mod local_tests {
    use super::*;

    fn status_buffer() -> [u8; 27] {
        let expected_status_packet_slice: [u8; 27] = [
            0, 0, 0, 23,  //                            Packet len
            101, //                                     Packet type
            0, 0, 0, 16, //                             ReqId
            0, 0, 0, 1, //                              Status code: SSH_FX_EOF
            0, 0, 0, 1,  //                             string message length
            65, //                                      string message content
            0, 0, 0, 5, //                              string lang length
            101, 110, 45, 85, 83, //                    string lang content
        ];
        expected_status_packet_slice
    }

    #[test]
    fn peeking_len() {
        let mut buffer_status = status_buffer();
        let source = SftpSource::from_data(&mut buffer_status);

        let read_packet_len = source.peek_packet_len().unwrap();
        let original_packet_len = 23;
        assert_eq!(original_packet_len, read_packet_len);
    }
    #[test]
    fn peeking_total_len() {
        let mut buffer_status = status_buffer();
        let source = SftpSource::from_data(&mut buffer_status);

        let read_total_packet_len = source.peek_total_packet_len().unwrap();
        let original_total_packet_len = 23 + 4;
        assert_eq!(original_total_packet_len, read_total_packet_len);
    }

    #[test]
    fn peeking_type() {
        let mut buffer_status = status_buffer();
        let source = SftpSource::from_data(&mut buffer_status);
        let read_packet_type = source.peek_packet_type().unwrap();
        let original_packet_type = SftpNum::from(101u8);
        assert_eq!(original_packet_type, read_packet_type);
    }

    #[test]
    fn peeking_req_id() {
        let mut buffer_status = status_buffer();
        let source = SftpSource::from_data(&mut buffer_status);
        let read_req_id = source.peek_packet_req_id().unwrap();
        let original_req_id = ReqId(16);
        assert_eq!(original_req_id, read_req_id);
    }
}
