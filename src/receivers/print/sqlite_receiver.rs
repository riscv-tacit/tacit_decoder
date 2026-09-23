use crate::backend::event::{Entry, EventKind, TrapReason};
use crate::common::prv::Prv;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use rusqlite::Connection;

struct EventRow {
    timestamp: u64,
    event_type: &'static str,
    from_addr: u64,
    to_addr: u64,
    prv: u8,
    ctx: u64,
}

pub struct SqliteReceiver {
    receiver: BusReceiver,
    conn: Connection,
    batch: Vec<EventRow>,
    batch_size: usize,
    curr_prv: Prv,
    curr_ctx: u64,
    row_count: u64,
}

impl SqliteReceiver {
    pub fn new(bus_rx: BusReader<Entry>, db_path: String, batch_size: usize) -> Self {
        let conn = Connection::open(&db_path).expect("Failed to open SQLite database");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             DROP TABLE IF EXISTS events;
             CREATE TABLE events (
                 id          INTEGER PRIMARY KEY,
                 timestamp   INTEGER NOT NULL,
                 event_type  TEXT NOT NULL,
                 from_addr   INTEGER,
                 to_addr     INTEGER,
                 prv         INTEGER,
                 ctx         INTEGER
             );",
        )
        .expect("Failed to create events table");

        Self {
            receiver: BusReceiver {
                name: "sqlite".to_string(),
                bus_rx,
                checksum: 0,
            },
            conn,
            batch: Vec::with_capacity(batch_size),
            batch_size,
            curr_prv: Prv::PrvMachine,
            curr_ctx: 0,
            row_count: 0,
        }
    }

    fn flush_batch(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let tx = self.conn.transaction().expect("Failed to begin transaction");
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO events (timestamp, event_type, from_addr, to_addr, prv, ctx) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .expect("Failed to prepare insert statement");
            for row in &self.batch {
                stmt.execute(rusqlite::params![
                    row.timestamp as i64,
                    row.event_type,
                    row.from_addr as i64,
                    row.to_addr as i64,
                    row.prv,
                    row.ctx as i64,
                ])
                .expect("Failed to insert row");
            }
        }
        tx.commit().expect("Failed to commit transaction");
        self.row_count += self.batch.len() as u64;
        self.batch.clear();
    }

    fn push_event(&mut self, timestamp: u64, event_type: &'static str, from_addr: u64, to_addr: u64) {
        self.batch.push(EventRow {
            timestamp,
            event_type,
            from_addr,
            to_addr,
            prv: self.curr_prv as u8,
            ctx: self.curr_ctx,
        });
        if self.batch.len() >= self.batch_size {
            self.flush_batch();
        }
    }
}

pub fn factory(
    _shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let db_path = config
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("trace.db")
        .to_string();
    let batch_size = config
        .get("batch_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(10000) as usize;
    Box::new(SqliteReceiver::new(bus_rx, db_path, batch_size))
}

crate::register_receiver!("sqlite", factory);

impl AbstractReceiver for SqliteReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind } => match kind {
                EventKind::TakenBranch { arc } => {
                    self.push_event(timestamp, "TB", arc.0, arc.1);
                }
                EventKind::NonTakenBranch { arc } => {
                    self.push_event(timestamp, "NTB", arc.0, arc.1);
                }
                EventKind::InferrableJump { arc } => {
                    self.push_event(timestamp, "IJ", arc.0, arc.1);
                }
                EventKind::UninferableJump { arc } => {
                    self.push_event(timestamp, "UJ", arc.0, arc.1);
                }
                EventKind::Trap {
                    reason,
                    prv_arc,
                    arc,
                    ctx,
                } => {
                    let event_type = match reason {
                        TrapReason::Interrupt => "TRAP_INT",
                        TrapReason::Exception => "TRAP_EXC",
                        TrapReason::Return => "TRAP_RET",
                    };
                    self.push_event(timestamp, event_type, arc.0, arc.1);
                    self.curr_prv = prv_arc.1;
                    if let Some(c) = ctx {
                        self.curr_ctx = c;
                    }
                }
                EventKind::SyncStart {
                    start_pc,
                    start_prv,
                    start_ctx,
                    ..
                } => {
                    self.curr_prv = start_prv;
                    self.curr_ctx = start_ctx;
                    self.push_event(timestamp, "SYNC_START", start_pc, 0);
                }
                EventKind::SyncEnd { end_pc } => {
                    self.push_event(timestamp, "SYNC_END", 0, end_pc);
                }
                EventKind::Pause { pause_pc } => {
                    self.push_event(timestamp, "PAUSE", pause_pc, 0);
                }
                EventKind::Resume { pc, prv, ctx, .. } => {
                    self.curr_prv = prv;
                    self.curr_ctx = ctx;
                    self.push_event(timestamp, "RESUME", 0, pc);
                }
                _ => {}
            },
        }
    }

    fn _flush(&mut self) {
        self.flush_batch();

        // Indices are not created automatically — on large traces it's too slow.
        // Create them in Python/sqlite3 when needed, e.g.:
        //   CREATE INDEX idx_events_event_type ON events(event_type);

        println!("--------------------------------");
        println!("SQLite receiver: {} events written", self.row_count);
        println!("--------------------------------");
    }
}
