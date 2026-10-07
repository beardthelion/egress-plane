pub fn probe() {
    let _ = (
        std::os::windows::process::ChildExt,
        std::os::windows::process::ExitCodeExt,
        std::os::windows::process::ExitStatusExt,
        std::os::windows::process::ProcThreadAttributeList,
        std::os::windows::process::ProcThreadAttributeListBuilder,
    );
}
