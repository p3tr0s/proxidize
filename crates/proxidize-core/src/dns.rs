//! Minimal DNS message codec: enough to answer A/AAAA queries and to read answers.

use crate::net::Ip;

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    /// Set for A and AAAA records.
    pub address: Option<Ip>,
    /// Set for CNAME records.
    pub target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

impl Message {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0xF
    }

    pub fn response_code(&self) -> u16 {
        self.flags & 0xF
    }

    pub fn parse(data: &[u8]) -> Option<Message> {
        if data.len() < 12 {
            return None;
        }
        let id = be16(data, 0)?;
        let flags = be16(data, 2)?;
        let qd = be16(data, 4)? as usize;
        let an = be16(data, 6)? as usize;
        if qd > 16 || an > 512 {
            return None;
        }
        let mut offset = 12;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let name = read_name(data, &mut offset)?;
            questions.push(Question { name, kind: be16(data, offset)?, class: be16(data, offset + 2)? });
            offset += 4;
        }
        let mut answers = Vec::with_capacity(an);
        for _ in 0..an {
            let name = read_name(data, &mut offset)?;
            let kind = be16(data, offset)?;
            let class = be16(data, offset + 2)?;
            let ttl = be32(data, offset + 4)?;
            let rd_len = be16(data, offset + 8)? as usize;
            offset += 10;
            let rdata = data.get(offset..offset + rd_len)?;
            let mut address = None;
            let mut target = None;
            if kind == TYPE_A && rd_len == 4 {
                address = Some(Ip::from_slice_v4(rdata));
            } else if kind == TYPE_AAAA && rd_len == 16 {
                address = Some(Ip::from_slice_v6(rdata));
            } else if kind == TYPE_CNAME {
                let mut at = offset;
                target = read_name(data, &mut at);
            }
            answers.push(Record { name, kind, class, ttl, address, target });
            offset += rd_len;
        }
        Some(Message { id, flags, questions, answers })
    }

    pub fn build_query(id: u16, name: &str, kind: u16) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(32 + name.len());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        write_name(&mut out, name)?;
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        Some(out)
    }

    /// A NOERROR response to `query` carrying `addresses` (may be empty) for its first question. Only addresses
    /// matching the question type are emitted.
    pub fn build_response(query: &Message, addresses: &[Ip], ttl: u32) -> Option<Vec<u8>> {
        let question = query.questions.first()?;
        let records: Vec<Ip> = addresses
            .iter()
            .copied()
            .filter(|a| if question.kind == TYPE_A { a.is_v4() } else { question.kind == TYPE_AAAA && !a.is_v4() })
            .collect();
        let mut out = Vec::with_capacity(64 + records.len() * 28);
        out.extend_from_slice(&query.id.to_be_bytes());
        let flags = 0x8000 | (query.flags & 0x7800) | (query.flags & 0x0100) | 0x0080;
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        write_name(&mut out, &question.name)?;
        out.extend_from_slice(&question.kind.to_be_bytes());
        out.extend_from_slice(&question.class.to_be_bytes());
        for address in records {
            out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to the question name
            out.extend_from_slice(&(if address.is_v4() { TYPE_A } else { TYPE_AAAA }).to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            if address.is_v4() {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&address.v4_value().to_be_bytes());
            } else {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&address.raw().to_be_bytes());
            }
        }
        Some(out)
    }
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    let name = name.trim_end_matches('.');
    let mut written = 0usize;
    if !name.is_empty() {
        for label in name.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 || !label.is_ascii() || written + 1 + bytes.len() > 254 {
                return None;
            }
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
            written += 1 + bytes.len();
        }
    }
    out.push(0);
    Some(())
}

fn read_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut name = String::new();
    let mut position = *offset;
    let mut jumps = 0;
    let mut jumped = false;
    loop {
        let length = *data.get(position)?;
        if length & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            let pointer = (((length & 0x3F) as usize) << 8) | *data.get(position + 1)? as usize;
            if !jumped {
                *offset = position + 2;
                jumped = true;
            }
            position = pointer;
            continue;
        }
        if length & 0xC0 != 0 {
            return None; // extended label types are not supported
        }
        if length == 0 {
            if !jumped {
                *offset = position + 1;
            }
            break;
        }
        let label = data.get(position + 1..position + 1 + length as usize)?;
        if name.len() + label.len() + 1 > 255 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
        position += 1 + length as usize;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_response_round_trip() {
        let q = Message::build_query(0x1234, "World.Realm.Example.", TYPE_A).unwrap();
        let parsed = Message::parse(&q).unwrap();
        assert!(!parsed.is_response());
        assert_eq!(parsed.questions[0].name, "world.realm.example");
        assert_eq!(parsed.questions[0].kind, TYPE_A);

        let addrs: Vec<Ip> = vec!["198.18.0.5".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let r = Message::build_response(&parsed, &addrs, 5).unwrap();
        let resp = Message::parse(&r).unwrap();
        assert!(resp.is_response());
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.answers.len(), 1, "AAAA filtered out of an A answer");
        assert_eq!(resp.answers[0].address.unwrap().to_string(), "198.18.0.5");
        assert_eq!(resp.answers[0].ttl, 5);
        assert_eq!(resp.answers[0].name, "world.realm.example", "compression pointer followed");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Message::build_query(1, &"a".repeat(64), TYPE_A).is_none());
        assert!(Message::parse(&[0; 5]).is_none());
        // pointer loop
        let mut q = Message::build_query(1, "x.y", TYPE_A).unwrap();
        q.truncate(12);
        q.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(Message::parse(&q).is_none());
    }

    #[test]
    fn cname_targets() {
        let q = Message::build_query(7, "a.example", TYPE_A).unwrap();
        let mut r = q.clone();
        r[2] = 0x81;
        r[7] = 1; // one answer
        r.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'b', 0xC0, 14]);
        let m = Message::parse(&r).unwrap();
        assert_eq!(m.answers[0].target.as_deref(), Some("b.example"));
    }
}
