fn main() {
    if let Err(err) = nm_daemon::run() {
        nm_daemon::report_error(&err);
        std::process::exit(1);
    }
}
