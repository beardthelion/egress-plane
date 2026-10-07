pub fn probe() {
    let _ = (
        std::os::unix::process::ChildExt,
        std::os::unix::process::ExitStatusExt,
        std::os::unix::process::parent_id,
    );
}
