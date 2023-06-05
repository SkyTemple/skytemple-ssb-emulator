macro_rules! dbg_trace {
    ($($arg:tt)+) => (
        #[cfg(debug_assertions)]
        {
            eprintln!("ssb_emu_trace [{:?}] - {:.200}", std::thread::current().id(), format!($($arg)+))
        }
    )
}
