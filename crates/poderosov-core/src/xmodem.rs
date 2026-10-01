//! Sending a file with XMODEM, as `rx` on the remote side expects it.
//!
//! [`XmodemSender`] is only the protocol: it is fed what the receiver sends
//! and the passing of time, and answers with what to send back. Moving the
//! bytes is up to the caller.
//!
//! Blocks are 128 bytes. The receiver picks the error check: `C` asks for
//! CRC-16, NAK for the original one-byte checksum.

use std::time::{Duration, Instant};

const SOH: u8 = 0x01;
const EOT: u8 = 0x04;
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const CAN: u8 = 0x18;
const CRC_REQUEST: u8 = b'C';
/// Fills the last block.
const PAD: u8 = 0x1a;

pub const BLOCK_SIZE: usize = 128;

/// How long the receiver gets to ask for the first block.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for an answer to a block before sending it again.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// How often one block may be sent before giving up.
const MAX_ATTEMPTS: u32 = 10;

/// What the caller has to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send these bytes to the receiver.
    Send(Vec<u8>),
    /// This many bytes of the file have been acknowledged.
    Progress { sent: usize, total: usize },
    /// The receiver has the whole file.
    Finished,
    /// The transfer is over without success.
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    WaitingForStart,
    WaitingForAck,
    WaitingForEotAck,
    Over,
}

/// The sending side of one XMODEM transfer.
pub struct XmodemSender {
    data: Vec<u8>,
    state: State,
    /// Index of the block in flight (0 for block number 1).
    block: usize,
    use_crc: bool,
    attempts: u32,
    /// When the last block or EOT went out, or when the transfer began.
    last_sent: Instant,
    /// CAN bytes received in a row: two of them abort the transfer.
    cancels: u32,
}

impl XmodemSender {
    pub fn new(data: Vec<u8>, now: Instant) -> Self {
        Self {
            data,
            state: State::WaitingForStart,
            block: 0,
            use_crc: false,
            attempts: 0,
            last_sent: now,
            cancels: 0,
        }
    }

    pub fn total(&self) -> usize {
        self.data.len()
    }

    pub fn is_over(&self) -> bool {
        self.state == State::Over
    }

    fn block_count(&self) -> usize {
        self.data.len().div_ceil(BLOCK_SIZE)
    }

    /// Handles bytes from the receiver.
    pub fn receive(&mut self, input: &[u8], now: Instant) -> Vec<Step> {
        let mut steps = Vec::new();
        for &byte in input {
            if self.state == State::Over {
                break;
            }
            if byte == CAN {
                self.cancels += 1;
                if self.cancels >= 2 {
                    self.state = State::Over;
                    steps.push(Step::Failed("cancelled by the receiver".to_owned()));
                }
                continue;
            }
            self.cancels = 0;
            match (self.state, byte) {
                (State::WaitingForStart, CRC_REQUEST | NAK) => {
                    self.use_crc = byte == CRC_REQUEST;
                    self.send_current(now, &mut steps);
                }
                (State::WaitingForAck, ACK) => {
                    self.block += 1;
                    let sent = (self.block * BLOCK_SIZE).min(self.data.len());
                    steps.push(Step::Progress { sent, total: self.data.len() });
                    self.attempts = 0;
                    self.send_current(now, &mut steps);
                }
                (State::WaitingForAck, NAK) | (State::WaitingForEotAck, NAK) => {
                    self.resend(now, &mut steps);
                }
                (State::WaitingForEotAck, ACK) => {
                    self.state = State::Over;
                    steps.push(Step::Finished);
                }
                // anything else is the receiver's chatter, or noise
                _ => {}
            }
        }
        steps
    }

    /// Lets time pass: resends what went unanswered, or gives up.
    pub fn tick(&mut self, now: Instant) -> Vec<Step> {
        let mut steps = Vec::new();
        let waited = now.saturating_duration_since(self.last_sent);
        match self.state {
            State::WaitingForStart if waited >= START_TIMEOUT => {
                self.state = State::Over;
                steps.push(Step::Failed("the receiver did not start".to_owned()));
            }
            State::WaitingForAck | State::WaitingForEotAck if waited >= BLOCK_TIMEOUT => {
                self.resend(now, &mut steps);
            }
            _ => {}
        }
        steps
    }

    /// Abandons the transfer, telling the receiver to stop too.
    pub fn cancel(&mut self) -> Vec<Step> {
        if self.state == State::Over {
            return Vec::new();
        }
        self.state = State::Over;
        vec![
            Step::Send(vec![CAN; 3]),
            Step::Failed("cancelled".to_owned()),
        ]
    }

    /// Sends the block in flight, or EOT once every block is through.
    fn send_current(&mut self, now: Instant, steps: &mut Vec<Step>) {
        self.attempts += 1;
        self.last_sent = now;
        if self.block < self.block_count() {
            self.state = State::WaitingForAck;
            steps.push(Step::Send(self.encode_block(self.block)));
        } else {
            self.state = State::WaitingForEotAck;
            steps.push(Step::Send(vec![EOT]));
        }
    }

    fn resend(&mut self, now: Instant, steps: &mut Vec<Step>) {
        if self.attempts >= MAX_ATTEMPTS {
            self.state = State::Over;
            steps.push(Step::Send(vec![CAN; 3]));
            steps.push(Step::Failed("the receiver kept rejecting a block".to_owned()));
            return;
        }
        self.send_current(now, steps);
    }

    fn encode_block(&self, index: usize) -> Vec<u8> {
        let start = index * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(self.data.len());
        let mut payload = [PAD; BLOCK_SIZE];
        payload[..end - start].copy_from_slice(&self.data[start..end]);

        // block numbers start at 1 and wrap around
        let number = ((index + 1) % 256) as u8;
        let mut block = Vec::with_capacity(BLOCK_SIZE + 5);
        block.extend_from_slice(&[SOH, number, 255 - number]);
        block.extend_from_slice(&payload);
        if self.use_crc {
            block.extend_from_slice(&crc16(&payload).to_be_bytes());
        } else {
            block.push(payload.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        }
        block
    }
}

/// CRC-16/XMODEM: polynomial 0x1021, starting from 0.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays the receiving side: checks every block and collects the file.
    fn receive_all(data: &[u8], crc: bool) -> Vec<u8> {
        let now = Instant::now();
        let mut sender = XmodemSender::new(data.to_vec(), now);
        let mut received = Vec::new();
        let mut expected_number = 1u8;
        let mut reply = vec![if crc { CRC_REQUEST } else { NAK }];
        loop {
            let steps = sender.receive(&reply, now);
            reply.clear();
            for step in steps {
                match step {
                    Step::Send(bytes) if bytes == [EOT] => reply.push(ACK),
                    Step::Send(bytes) => {
                        assert_eq!(bytes[0], SOH);
                        assert_eq!(bytes[1], expected_number);
                        assert_eq!(bytes[2], 255 - expected_number);
                        let payload = &bytes[3..3 + BLOCK_SIZE];
                        if crc {
                            assert_eq!(bytes.len(), BLOCK_SIZE + 5);
                            assert_eq!(&bytes[BLOCK_SIZE + 3..], &crc16(payload).to_be_bytes());
                        } else {
                            assert_eq!(bytes.len(), BLOCK_SIZE + 4);
                        }
                        received.extend_from_slice(payload);
                        expected_number = expected_number.wrapping_add(1);
                        reply.push(ACK);
                    }
                    Step::Progress { .. } => {}
                    Step::Finished => return received,
                    Step::Failed(reason) => panic!("transfer failed: {reason}"),
                }
            }
        }
    }

    #[test]
    fn crc_matches_the_standard_check_value() {
        assert_eq!(crc16(b"123456789"), 0x31c3);
    }

    #[test]
    fn a_file_arrives_whole_with_crc_and_with_checksum() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        for crc in [true, false] {
            let received = receive_all(&data, crc);
            assert_eq!(&received[..data.len()], &data[..]);
            // the last block is padded out
            assert_eq!(received.len(), 8 * BLOCK_SIZE);
            assert!(received[data.len()..].iter().all(|&byte| byte == PAD));
        }
    }

    #[test]
    fn block_numbers_wrap_after_255() {
        let data = vec![0x55; 300 * BLOCK_SIZE];
        assert_eq!(receive_all(&data, true), data);
    }

    #[test]
    fn an_empty_file_is_just_eot() {
        let now = Instant::now();
        let mut sender = XmodemSender::new(Vec::new(), now);
        assert_eq!(sender.receive(&[CRC_REQUEST], now), [Step::Send(vec![EOT])]);
        assert_eq!(sender.receive(&[ACK], now), [Step::Finished]);
    }

    #[test]
    fn a_rejected_block_is_sent_again_and_eventually_given_up() {
        let now = Instant::now();
        let mut sender = XmodemSender::new(vec![1; 10], now);
        let first = sender.receive(&[CRC_REQUEST], now);
        for _ in 1..MAX_ATTEMPTS {
            assert_eq!(sender.receive(&[NAK], now), first);
        }
        let last = sender.receive(&[NAK], now);
        assert!(matches!(last.last(), Some(Step::Failed(_))), "{last:?}");
        assert!(sender.is_over());
    }

    #[test]
    fn silence_resends_and_a_receiver_that_never_starts_times_out() {
        let start = Instant::now();
        let mut sender = XmodemSender::new(vec![1; 10], start);
        assert!(sender.tick(start + Duration::from_secs(30)).is_empty());
        let steps = sender.tick(start + START_TIMEOUT);
        assert!(matches!(steps[..], [Step::Failed(_)]), "{steps:?}");

        let mut sender = XmodemSender::new(vec![1; 10], start);
        let block = sender.receive(&[CRC_REQUEST], start);
        assert_eq!(sender.tick(start + BLOCK_TIMEOUT), block);
    }

    #[test]
    fn two_cans_from_the_receiver_abort() {
        let now = Instant::now();
        let mut sender = XmodemSender::new(vec![1; 10], now);
        sender.receive(&[CRC_REQUEST], now);
        let steps = sender.receive(&[CAN, CAN], now);
        assert!(matches!(steps[..], [Step::Failed(_)]), "{steps:?}");
    }

    #[test]
    fn chatter_before_the_start_is_ignored() {
        let now = Instant::now();
        let mut sender = XmodemSender::new(vec![1; 10], now);
        assert!(sender.receive(b"rx: ready to receive file\r\n", now).is_empty());
    }
}
