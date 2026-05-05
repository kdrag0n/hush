use anyhow::{Result, bail};

pub fn raise_nofile_soft_limit_to_hard() -> Result<()> {
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
        bail!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if limit.rlim_cur >= limit.rlim_max {
        tracing::debug!(
            soft = limit.rlim_cur,
            hard = limit.rlim_max,
            "fd limit already raised"
        );
        return Ok(());
    }

    let old_soft = limit.rlim_cur;
    limit.rlim_cur = limit.rlim_max;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } < 0 {
        bail!(
            "setrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    tracing::info!(
        old_soft,
        soft = limit.rlim_cur,
        hard = limit.rlim_max,
        "raised fd soft limit"
    );
    Ok(())
}
