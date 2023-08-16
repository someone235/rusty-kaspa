extern crate kaspa_consensus;
extern crate kaspa_core;
extern crate kaspa_hashes;

use daemon::create_daemon;

use kaspa_core::trace;

use crate::args::parse_args;

mod args;

// TODO: refactor the shutdown sequence into a predefined controlled sequence

pub fn main() {
    #[cfg(feature = "heap")]
    let _profiler = dhat::Profiler::builder().file_name("kaspad-heap.json").build();

    let args = parse_args();
    create_daemon(args).run();
    trace!("Kaspad is finished...");
}
