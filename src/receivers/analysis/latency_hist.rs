/* Bounded latency distribution, shared by the stats receivers.

   Keeping every interval (a Vec<u64> per key) costs 8 bytes per sample -- 2.5 GB on a
   300M-dispatch capture -- and still only ever gets summarised. A histogram is 4 KB per
   key regardless of traffic, makes ANY percentile free at flush (p5 and p25 as easily as
   p50), and can be dumped whole so the shape of the distribution survives into the
   analysis instead of being flattened to a handful of numbers. */
pub const HIST_BINS: usize = 512;

pub struct LatencyHist {
    pub hist: Vec<u64>,   // index = cycles, for cycles < HIST_BINS
    pub over_n: u64,      // samples at or beyond HIST_BINS; their values live in sum/max
    pub max: u64,
    pub n: u64,
    pub sum: u64,
}

impl Default for LatencyHist {
    fn default() -> Self {
        Self { hist: vec![0; HIST_BINS], over_n: 0, max: 0, n: 0, sum: 0 }
    }
}

impl LatencyHist {
    pub fn add(&mut self, v: u64) {
        self.n += 1;
        self.sum += v;
        if v > self.max {
            self.max = v;
        }
        if (v as usize) < HIST_BINS {
            self.hist[v as usize] += 1;
        } else {
            self.over_n += 1;
        }
    }

    pub fn min(&self) -> u64 {
        for (c, &k) in self.hist.iter().enumerate() {
            if k > 0 {
                return c as u64;
            }
        }
        self.max
    }

    /* nearest-rank on the implied sorted sample, matching the previous Vec-based code */
    pub fn quantile(&self, p: f64) -> u64 {
        if self.n == 0 {
            return 0;
        }
        let target = (((self.n - 1) as f64) * p).round() as u64;
        let mut acc: u64 = 0;
        for (c, &k) in self.hist.iter().enumerate() {
            if k == 0 {
                continue;
            }
            acc += k;
            if acc > target {
                return c as u64;
            }
        }
        self.max // the rank fell in the overflow tail
    }
}

