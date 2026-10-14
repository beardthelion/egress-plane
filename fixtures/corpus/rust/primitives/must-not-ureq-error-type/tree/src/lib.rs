pub fn probe() {
    let _ = (
        ureq::Agent,
        ureq::AgentBuilder,
        ureq::Error,
        ureq::Proxy,
        ureq::Request,
        ureq::Response,
        ureq::json,
    );
}
