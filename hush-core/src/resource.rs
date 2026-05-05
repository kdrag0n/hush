pub fn raise_nofile_soft_limit_to_hard() -> Result<()> {
    crate::os::raise_nofile_soft_limit_to_hard()
}

use anyhow::Result;
