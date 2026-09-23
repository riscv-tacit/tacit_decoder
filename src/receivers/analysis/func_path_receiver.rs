use crate::backend::event::{Entry, EventKind};
use crate::common::symbol_index::SymbolIndex;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::stack_unwinder::StackUnwinder;
use bus::BusReader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;

struct PathStats {
    count: u64,
    min: u64,
    sum: u64,
}

impl PathStats {
    fn new(duration: u64) -> Self {
        Self {
            count: 1,
            min: duration,
            sum: duration,
        }
    }

    fn update(&mut self, duration: u64) {
        self.count += 1;
        self.min = self.min.min(duration);
        self.sum += duration;
    }
}

struct BBRecord {
    start: u64,
    end: u64,
    duration: u64,
}

struct Invocation {
    bbs: Vec<BBRecord>,
}

enum Phase {
    Idle,
    Active,
    PostExit { remaining: usize },
}

pub struct FuncPathReceiver {
    path_writer: BufWriter<File>,
    bb_writer: BufWriter<File>,
    post_exit_writer: BufWriter<File>,
    receiver: BusReceiver,
    unwinder: StackUnwinder,
    func_name: String,
    ctx: u64,
    filter_contains: Option<String>,
    phase: Phase,
    entry_ts: u64,
    seen_filter: bool,
    gap_aborted: u64,
    current_branches: Vec<bool>,
    path_records: HashMap<Vec<bool>, PathStats>,
    // per-invocation BB tracking
    prev_addr: u64,
    prev_timestamp: u64,
    current_bbs: Vec<BBRecord>,
    invocations: Vec<Invocation>,
    // post-exit BB tracking
    post_exit_n: usize,
    post_exit_bbs: Vec<BBRecord>,
    post_exit_records: Vec<Vec<BBRecord>>,
}

impl FuncPathReceiver {
    pub fn new(
        bus_rx: BusReader<Entry>,
        symbols: Arc<SymbolIndex>,
        func_name: String,
        ctx: u64,
        filter_contains: Option<String>,
        path: String,
        bb_path: String,
        post_exit_path: String,
        post_exit_n: usize,
    ) -> Self {
        Self {
            path_writer: BufWriter::new(File::create(path).unwrap()),
            bb_writer: BufWriter::new(File::create(bb_path).unwrap()),
            post_exit_writer: BufWriter::new(File::create(post_exit_path).unwrap()),
            receiver: BusReceiver {
                name: "func_path".to_string(),
                bus_rx,
                checksum: 0,
            },
            unwinder: StackUnwinder::new(symbols).expect("stack unwinder"),
            func_name,
            ctx,
            filter_contains,
            phase: Phase::Idle,
            entry_ts: 0,
            seen_filter: false,
            gap_aborted: 0,
            current_branches: Vec::new(),
            path_records: HashMap::new(),
            prev_addr: 0,
            prev_timestamp: 0,
            current_bbs: Vec::new(),
            invocations: Vec::new(),
            post_exit_n,
            post_exit_bbs: Vec::new(),
            post_exit_records: Vec::new(),
        }
    }

    fn close_bb(&mut self, from_addr: u64, to_addr: u64, timestamp: u64) {
        let duration = timestamp.saturating_sub(self.prev_timestamp);
        self.current_bbs.push(BBRecord {
            start: self.prev_addr,
            end: from_addr,
            duration,
        });
        self.prev_addr = to_addr;
        self.prev_timestamp = timestamp;
    }

    fn commit_post_exit(&mut self) {
        self.post_exit_records
            .push(std::mem::take(&mut self.post_exit_bbs));
        self.phase = Phase::Idle;
    }

    fn close_post_exit_bb(&mut self, from_addr: u64, to_addr: u64, timestamp: u64) {
        let duration = timestamp.saturating_sub(self.prev_timestamp);
        self.post_exit_bbs.push(BBRecord {
            start: self.prev_addr,
            end: from_addr,
            duration,
        });
        self.prev_addr = to_addr;
        self.prev_timestamp = timestamp;
    }

    fn commit_invocation(&mut self, exit_ts: u64) {
        let dominated = match &self.filter_contains {
            Some(_) => self.seen_filter,
            None => true,
        };
        if dominated {
            let duration = exit_ts.saturating_sub(self.entry_ts);
            let branches = std::mem::take(&mut self.current_branches);
            if let Some(stats) = self.path_records.get_mut(&branches) {
                stats.update(duration);
            } else {
                self.path_records.insert(branches, PathStats::new(duration));
            }
            self.invocations.push(Invocation {
                bbs: std::mem::take(&mut self.current_bbs),
            });
            // transition to post-exit tracking
            self.post_exit_bbs.clear();
            self.phase = Phase::PostExit {
                remaining: self.post_exit_n,
            };
        } else {
            self.current_branches.clear();
            self.current_bbs.clear();
            self.phase = Phase::Idle;
        }
        self.seen_filter = false;
    }
}

pub fn factory(
    shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let func_name = config
        .get("func_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let ctx = config
        .get("ctx")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let filter_contains = config
        .get("filter_contains")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let path = config
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("trace.func_path.csv")
        .to_string();
    let bb_path = config
        .get("bb_path")
        .and_then(|v| v.as_str())
        .unwrap_or("trace.func_path.bb.csv")
        .to_string();
    let post_exit_path = config
        .get("post_exit_path")
        .and_then(|v| v.as_str())
        .unwrap_or("trace.func_path.post_exit.csv")
        .to_string();
    let post_exit_n = config
        .get("post_exit_n")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as usize;
    Box::new(FuncPathReceiver::new(
        bus_rx,
        shared.symbol_index.clone(),
        func_name,
        ctx,
        filter_contains,
        path,
        bb_path,
        post_exit_path,
        post_exit_n,
    ))
}

crate::register_receiver!("func_path", factory);

impl AbstractReceiver for FuncPathReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind } => {
                // A gap makes the current invocation / post-exit window
                // unobservable: drop the invocation (it would get a bogus
                // duration and path), keep whatever post-exit blocks were seen.
                if let EventKind::Pause { .. } = kind {
                    match self.phase {
                        Phase::Active => {
                            self.current_branches.clear();
                            self.current_bbs.clear();
                            self.seen_filter = false;
                            self.phase = Phase::Idle;
                            self.gap_aborted += 1;
                        }
                        Phase::PostExit { .. } => self.commit_post_exit(),
                        Phase::Idle => {}
                    }
                }

                // Close BBs based on current phase
                match self.phase {
                    Phase::Active => {
                        match &kind {
                            EventKind::TakenBranch { arc } => {
                                self.current_branches.push(true);
                                self.close_bb(arc.0, arc.1, timestamp);
                            }
                            EventKind::NonTakenBranch { arc } => {
                                self.current_branches.push(false);
                                self.close_bb(arc.0, arc.1, timestamp);
                            }
                            EventKind::InferrableJump { arc } => {
                                self.close_bb(arc.0, arc.1, timestamp);
                            }
                            EventKind::UninferableJump { arc } => {
                                self.close_bb(arc.0, arc.1, timestamp);
                            }
                            EventKind::Trap { arc, .. } => {
                                self.close_bb(arc.0, arc.1, timestamp);
                            }
                            _ => {}
                        }
                    }
                    Phase::PostExit { remaining } => {
                        let has_arc = matches!(
                            &kind,
                            EventKind::TakenBranch { .. }
                                | EventKind::NonTakenBranch { .. }
                                | EventKind::InferrableJump { .. }
                                | EventKind::UninferableJump { .. }
                                | EventKind::Trap { .. }
                        );
                        if has_arc {
                            match &kind {
                                EventKind::TakenBranch { arc }
                                | EventKind::NonTakenBranch { arc }
                                | EventKind::InferrableJump { arc }
                                | EventKind::UninferableJump { arc } => {
                                    self.close_post_exit_bb(arc.0, arc.1, timestamp);
                                }
                                EventKind::Trap { arc, .. } => {
                                    self.close_post_exit_bb(arc.0, arc.1, timestamp);
                                }
                                _ => {}
                            }
                            let remaining = remaining - 1;
                            if remaining == 0 {
                                self.commit_post_exit();
                            } else {
                                self.phase = Phase::PostExit { remaining };
                            }
                        }
                    }
                    Phase::Idle => {}
                }

                // Feed to stack unwinder
                let update = self.unwinder.step(&Entry::Event { timestamp, kind });

                if let Some(ref upd) = update {
                    // Check for target function exit (only when Active)
                    if matches!(self.phase, Phase::Active) {
                        for frame in &upd.frames_closed {
                            if frame.symbol.name == self.func_name {
                                self.commit_invocation(timestamp);
                                break;
                            }
                        }
                    }

                    // Check for target function entry
                    if let Some(ref frame) = upd.frames_opened {
                        if !matches!(self.phase, Phase::Active)
                            && frame.symbol.name == self.func_name
                            && self.unwinder.curr_ctx == self.ctx
                        {
                            // If in PostExit, commit whatever we have
                            if matches!(self.phase, Phase::PostExit { .. }) {
                                self.commit_post_exit();
                            }
                            self.phase = Phase::Active;
                            self.entry_ts = timestamp;
                            self.prev_addr = frame.addr;
                            self.prev_timestamp = timestamp;
                            self.current_branches.clear();
                            self.current_bbs.clear();
                            self.seen_filter = false;
                        }
                        if matches!(self.phase, Phase::Active) {
                            if let Some(ref filter) = self.filter_contains {
                                if frame.symbol.name == *filter {
                                    self.seen_filter = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn _flush(&mut self) {
        if self.gap_aborted > 0 {
            println!(
                "func_path: {} invocation(s) of {} cut by trace gaps and dropped",
                self.gap_aborted, self.func_name
            );
        }
        // Write path summary
        writeln!(self.path_writer, "count,mean,netvar,path").unwrap();
        for (branches, stats) in self.path_records.iter() {
            let mean = stats.sum as f64 / stats.count as f64;
            let netvar = stats.sum as f64 - (stats.count as f64 * stats.min as f64);
            let path_str: String = branches
                .iter()
                .map(|b| if *b { '1' } else { '0' })
                .collect();
            writeln!(
                self.path_writer,
                "{},{},{},{}",
                stats.count, mean, netvar, path_str
            )
            .unwrap();
        }
        self.path_writer.flush().unwrap();

        // Write per-invocation BB details
        writeln!(self.bb_writer, "invocation,bb_start,bb_end,duration").unwrap();
        for (i, inv) in self.invocations.iter().enumerate() {
            for bb in &inv.bbs {
                writeln!(
                    self.bb_writer,
                    "{},{:#x},{:#x},{}",
                    i, bb.start, bb.end, bb.duration
                )
                .unwrap();
            }
        }
        self.bb_writer.flush().unwrap();

        // Write post-exit BB details
        writeln!(self.post_exit_writer, "invocation,bb_index,bb_start,bb_end,duration").unwrap();
        for (i, bbs) in self.post_exit_records.iter().enumerate() {
            for (j, bb) in bbs.iter().enumerate() {
                writeln!(
                    self.post_exit_writer,
                    "{},{},{:#x},{:#x},{}",
                    i, j, bb.start, bb.end, bb.duration
                )
                .unwrap();
            }
        }
        self.post_exit_writer.flush().unwrap();

        println!("--------------------------------");
        println!(
            "func_path: {} unique paths, {} invocations of '{}' (ctx={}) (filter=contains '{}')",
            self.path_records.len(),
            self.invocations.len(),
            self.func_name,
            self.ctx,
            self.filter_contains.as_ref().unwrap_or(&"none".to_string())
        );
        println!("--------------------------------");
    }
}
