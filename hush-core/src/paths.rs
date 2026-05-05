use std::path::{Path, PathBuf};

pub fn default_data_dir() -> PathBuf {
    if crate::os::is_root() {
        PathBuf::from("/etc/hush")
    } else {
        xdg_dirs()
            .get_state_home()
            .unwrap_or_else(|| current_home().join(".local/state/hush"))
    }
}

pub fn default_server_config_path() -> PathBuf {
    server_config_path(&default_data_dir())
}

pub fn server_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("server")
}

pub fn server_config_path(data_dir: &Path) -> PathBuf {
    server_dir(data_dir).join("config.toml")
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
