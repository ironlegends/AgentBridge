use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct LaunchOptions {
    pub background: bool,
    pub config: Option<PathBuf>,
}

pub fn parse(args: &[OsString]) -> Result<LaunchOptions, String> {
    let mut options = LaunchOptions::default();
    let mut values = args.iter();
    while let Some(value) = values.next() {
        match value.to_str() {
            Some("--background") if !options.background => options.background = true,
            Some("--config") if options.config.is_none() => {
                let path = PathBuf::from(values.next().ok_or("--config requires an absolute local file.")?);
                if !crate::operator_connection::local_absolute_path(&path) {
                    return Err("--config requires an absolute local file.".into());
                }
                options.config = Some(path);
            }
            _ => return Err("Use only --background and one --config absolute-local-file.".into()),
        }
    }
    Ok(options)
}

pub fn foreground_activation(args: &[String]) -> bool {
    !args.iter().skip(1).any(|value| value == "--background")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> { values.iter().map(OsString::from).collect() }

    #[test]
    fn parses_explicit_background_config_and_rejects_ambiguous_launches() {
        let path = std::env::temp_dir().join("workstation-app.json");
        let configured = vec![OsString::from("--background"), OsString::from("--config"), path.clone().into_os_string()];
        assert_eq!(parse(&configured).unwrap(), LaunchOptions { background: true, config: Some(path) });
        for invalid in [
            args(&["--config"]), args(&["--background", "--background"]),
            args(&["--config", "relative.json"]), args(&["--unknown"]),
            args(&["--config", "a", "--config", "b"]),
        ] { assert!(parse(&invalid).is_err(), "invalid launch must not select defaults"); }
    }

    #[test]
    fn secondary_background_does_not_show_or_reapply_configuration() {
        assert!(!foreground_activation(&["app.exe".into(), "--background".into(), "--config".into(), "missing".into()]));
        assert!(foreground_activation(&["app.exe".into(), "--config".into(), "missing".into()]));
    }
}
