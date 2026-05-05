use std::path::PathBuf;

pub fn default_data_dir() -> PathBuf {
    if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/etc/hush")
    } else {
        xdg_dirs()
            .get_state_home()
            .unwrap_or_else(|| current_home().join(".local/state/hush"))
    }
}

pub fn default_server_config_path() -> PathBuf {
    if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/etc/hush/server_config.toml")
    } else {
        let dirs = xdg_dirs();
        dirs.find_config_file("server_config.toml")
            .unwrap_or_else(|| {
                dirs.get_config_home()
                    .unwrap_or_else(|| current_home().join(".config/hush"))
                    .join("server_config.toml")
            })
    }
}

pub fn ssh_dir_for_home(home: PathBuf) -> PathBuf {
    home.join(".ssh")
}

pub fn current_home() -> PathBuf {
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn xdg_dirs() -> xdg::BaseDirectories {
    xdg::BaseDirectories::with_prefix("hush")
}
