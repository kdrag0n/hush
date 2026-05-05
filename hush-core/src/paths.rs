use std::path::PathBuf;

pub fn default_data_dir() -> PathBuf {
    if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/etc/hush")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".hush")
    }
}

pub fn default_server_config_path() -> PathBuf {
    default_data_dir().join("server_config.toml")
}

pub fn ssh_dir_for_home(home: PathBuf) -> PathBuf {
    home.join(".ssh")
}

pub fn current_home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}
