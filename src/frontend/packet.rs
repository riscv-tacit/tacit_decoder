use anyhow::{anyhow, Result};
use log::trace;
use std::fs::File;
use std::io::{BufReader, Read};

use crate::common::prv::*;
use crate::frontend::br_mode::*;
use crate::frontend::c_header::*;
use crate::frontend::f_header::*;
use crate::frontend::runtime_cfg::*;
use crate::frontend::sync_type::*;
use crate::frontend::trap_type::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SubFunc3 {
    None,
    TrapType(TrapType),
    SyncType(SyncType), // unused for now
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub is_compressed: bool,
    pub c_header: CHeader,
    pub f_header: FHeader,
    pub func3: SubFunc3,
    pub target_address: u64,
    pub from_address: u64,
    pub target_prv: Prv,
    pub _from_ctx: u64, // used for debugging only
    pub target_ctx: u64,
    pub from_prv: Prv,
    pub timestamp: u64,
}

// Initialize a packet with default values
impl Packet {
    pub fn new() -> Packet {
        Packet {
            is_compressed: false,
            c_header: CHeader::CNa,
            f_header: FHeader::FRes1,
            func3: SubFunc3::None,
            target_address: 0,
            from_address: 0,
            target_prv: Prv::PrvUser,
            _from_ctx: 0,
            target_ctx: 0,
            from_prv: Prv::PrvUser,
            timestamp: 0,
        }
    }
}

fn read_u8(stream: &mut BufReader<File>) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

const VAR_MASK: u8 = 0b1000_0000;
const VAR_LAST: u8 = 0b1000_0000;
const VAR_OFFSET: u8 = 7;
const VAR_VAL_MASK: u8 = 0b0111_1111;

fn read_varint(stream: &mut BufReader<File>) -> Result<(u64, u64)> {
    let mut scratch = [0u8; 10];
    let mut count = 0usize;
    loop {
        let byte = read_u8(stream)?;
        if count == scratch.len() {
            return Err(anyhow!("varint exceeded maximum length"));
        }
        scratch[count] = byte;
        count += 1;
        if byte & VAR_MASK == VAR_LAST {
            break;
        }
    }
    let mut value: u64 = 0;
    for &byte in scratch[..count].iter().rev() {
        value = (value << VAR_OFFSET) | u64::from(byte & VAR_VAL_MASK);
    }
    Ok((value, count as u64))
}

fn read_prv(stream: &mut BufReader<File>) -> Result<(Prv, Prv)> {
    let result = read_u8(stream)?;
    let from_prv = Prv::from((result & 0b111) as u64);
    let target_prv = Prv::from(((result >> 3) & 0b111) as u64);
    assert!(
        0b10 == (result >> 6 & 0b11),
        "checksum for prv byte should be 0b10"
    );
    Ok((from_prv, target_prv))
}

// returns the number of bytes read
pub fn read_packet(stream: &mut BufReader<File>, packet: &mut Packet) -> Result<(u64)> {
    let first_byte = read_u8(stream)?;
    // trace!("first_byte: {:08b}", first_byte);
    let mut bytes_read = 1;
    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    match c_header {
        CHeader::CTb | CHeader::CNt | CHeader::CIj => {
            packet.timestamp = (first_byte & C_TIMESTAMP_MASK) as u64 >> 2;
            packet.f_header = FHeader::from(c_header.clone());
            packet.c_header = c_header.clone();
            packet.is_compressed = true;
        }
        CHeader::CNa => {
            packet.is_compressed = false;
            let f_header = FHeader::from((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET);
            match f_header {
                FHeader::FTb | FHeader::FNt | FHeader::FIj => {
                    let (timestamp, count) = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    bytes_read += count;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FUj => {
                    let (target_address, count) = read_varint(stream)?;
                    packet.target_address = target_address;
                    bytes_read += count;
                    let (timestamp, count) = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    bytes_read += count;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FSync => {
                    let sync_type =
                        SyncType::from((first_byte & SYNC_TYPE_MASK) >> SYNC_TYPE_OFFSET);
                    assert!(
                        sync_type != SyncType::SyncStart,
                        "SyncStart should not be observed other than in read_first_packet"
                    );
                    packet.func3 = SubFunc3::SyncType(sync_type);
                    let (from_prv, target_prv) = read_prv(stream)?;
                    assert!(from_prv == Prv::PrvUser, "from_prv should be PrvUser");
                    packet.from_prv = from_prv;
                    packet.target_prv = target_prv;
                    let (target_ctx, count) = read_varint(stream)?;
                    packet.target_ctx = target_ctx;
                    bytes_read += count;
                    let (target_address, count) = read_varint(stream)?;
                    packet.target_address = target_address;
                    bytes_read += count;
                    let (timestamp, count) = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    bytes_read += count;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FTrap => {
                    let trap_type =
                        TrapType::from((first_byte & TRAP_TYPE_MASK) >> TRAP_TYPE_OFFSET);
                    packet.func3 = SubFunc3::TrapType(trap_type);
                    let (from_prv, target_prv) = read_prv(stream)?;
                    packet.from_prv = from_prv;
                    bytes_read += 1;
                    packet.target_prv = target_prv;
                    if trap_type == TrapType::TReturn && target_prv == Prv::PrvUser {
                        let (target_ctx, count) = read_varint(stream)?;
                        packet.target_ctx = target_ctx;
                        bytes_read += count;
                    }
                    let (from_address, count) = read_varint(stream)?;
                    packet.from_address = from_address;
                    bytes_read += count;
                    let (target_address, count) = read_varint(stream)?;
                    packet.target_address = target_address;
                    bytes_read += count;
                    let (timestamp, count) = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    bytes_read += count;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                _ => {
                    panic!("Invalid FHeader value: {}", first_byte);
                }
            }
        }
    }
    Ok(bytes_read)
}

pub fn read_first_packet(stream: &mut BufReader<File>) -> Result<(Packet, DecoderRuntimeCfg)> {
    let mut packet = Packet::new();
    let first_byte = read_u8(stream)?;
    trace!("first_byte: {:08b}", first_byte);
    let mut bytes_read = 1;
    
    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    if c_header != CHeader::CNa {
        return Err(anyhow::anyhow!(
            "first packet must be CNa, got {:?}",
            c_header
        ));
    }

    let f_header = FHeader::from((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET);
    if f_header != FHeader::FSync {
        return Err(anyhow::anyhow!(
            "first packet must be FSync, got {:?}",
            f_header
        ));
    }

    let sync_type = SyncType::from((first_byte & SYNC_TYPE_MASK) >> SYNC_TYPE_OFFSET);
    if sync_type != SyncType::SyncStart {
        return Err(anyhow::anyhow!(
            "first packet must be SYNC_START, got {:?}",
            sync_type
        ));
    }

    packet.is_compressed = false;
    packet.c_header = c_header;
    packet.f_header = f_header;
    packet.func3 = SubFunc3::SyncType(sync_type);
    assert!(
        packet.func3 == SubFunc3::SyncType(SyncType::SyncStart),
        "func3 should be SyncStart"
    );

    let (from_prv, target_prv) = read_prv(stream)?;
    packet.from_prv = from_prv;
    assert!(
        from_prv == Prv::PrvUser,
        "from_prv should be PrvUser, got {:?}",
        from_prv
    );
    bytes_read += 1;
    trace!("target_prv: {:?}", target_prv);
    packet.target_prv = target_prv;
    let (target_ctx, count) = read_varint(stream)?;
    packet.target_ctx = target_ctx;
    bytes_read += count;
    let runtime_cfg_raw = read_u8(stream)?;
    let br_mode = BrMode::from((runtime_cfg_raw & BP_MODE_MASK) as u64);
    let bp_entries = ((runtime_cfg_raw & BP_ENTRY_MASK) >> BP_ENTRY_OFFSET) as u64 * BP_BASE_VALUE;

    let (target_address, count) = read_varint(stream)?;
    packet.target_address = target_address;
    bytes_read += count;
    let (timestamp, count) = read_varint(stream)?;
    packet.timestamp = timestamp;
    bytes_read += count;

    Ok((
        packet,
        DecoderRuntimeCfg {
            br_mode,
            bp_entries,
        },
    ))
}
