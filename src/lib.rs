// Copyright (C) 2020—2025 Andrej Shadura
// SPDX-License-Identifier: MIT
use flopen::OpenAndLock;
use libc::{getpid, pid_t};
use log::warn;
use std::fs::{read_to_string, remove_file, File, Metadata, OpenOptions, Permissions};
use std::io;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// A PID file protected with a lock.
///
/// An instance of `Pidfile` can be used to manage a PID file: create it,
/// lock it, detect already running daemons. It is backed by [`pidfile`][]
/// functions of `libbsd`/`libutil` which use `flopen` to lock the PID
/// file.
///
/// When a PID file is created, the process ID of the current process is
/// *not* written there, making it possible to lock the PID file before
/// forking and only write the ID of the forked process when it is ready.
///
/// The PID file is deleted automatically when the `Pidfile` comes out of
/// the scope. To close the PID file without deleting it, for example, in
/// the parent process of a forked daemon, call `close()`.
///
/// # Example
///
/// When the parent process exits without calling destructors, e.g. by
/// using [`exit`][] or when forking with [`daemon`(3)], `Pidfile` can
/// be used in the following way:
/// ```rust
/// # use std::error::Error;
/// # use std::fs::Permissions;
/// # use std::os::unix::fs::PermissionsExt;
/// # use tempfile::tempdir;
/// // This example uses daemon(3) wrapped by nix to daemonise:
/// use nix::unistd::daemon;
/// use pidfile_rs::{Pidfile, PidfileError};
///
/// // ...
///
/// # let dir = tempdir()?;
/// # let mut pidfile_path = dir.path().to_owned();
/// # pidfile_path.push("file.pid");
/// # println!("pidfile_path = {:?}", pidfile_path);
/// let pidfile = Some(Pidfile::new(
///     &pidfile_path,
///     Permissions::from_mode(0o600)
/// )?);
///
/// // do some pre-fork preparations
/// // ...
///
/// // in the parent process, the PID file is closed without deleting it
/// daemon(false, true)?;
///
/// pidfile.unwrap().write();
///
/// // do some work
/// println!("The daemon’s work is done, now it’s time to go home.");
///
/// // the PID file will be deleted when this function returns
///
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// [`exit`]: https://doc.rust-lang.org/std/process/fn.exit.html
/// [`pidfile`]: https://linux.die.net/man/3/pidfile
/// [`daemon`(3)]: https://linux.die.net/man/3/daemon
#[derive(Debug)]
pub struct Pidfile {
    file: File,
    path: PathBuf,
    metadata: Metadata,
    autoremove: bool,
}

#[derive(Error, Debug)]
pub enum PidfileError {
    /// The file cannot be locked. The `pid` field contains the PID of the
    /// already running process or `None` in case it did not write
    /// its PID yet.
    #[error("daemon already running with {}", match .pid {
        Some(pid) => format!("PID {pid}"),
        None => "unknown PID".into()
    })]
    AlreadyRunning { pid: Option<pid_t> },
    /// An I/O error has occurred.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Pidfile {
    /// Creates a new PID file and locks it.
    ///
    /// If the PID file cannot be locked, returns `PidfileError::AlreadyRunning` with
    /// a PID of the already running process, or `None` if no PID has been written to
    /// the PID file yet.
    pub fn new(path: &Path, permissions: Permissions) -> Result<Pidfile, PidfileError> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(permissions.mode())
            .try_open_and_lock(path);
        match file {
            Ok(file) => {
                file.set_len(0)?;
                let metadata = file.metadata()?;
                Ok(Pidfile {
                    file,
                    path: path.into(),
                    metadata,
                    autoremove: true,
                })
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    Err(PidfileError::AlreadyRunning {
                        pid: Pidfile::read(path),
                    })
                } else {
                    Err(PidfileError::Io(err))
                }
            }
        }
    }

    fn read(path: &Path) -> Option<pid_t> {
        read_to_string(path).ok()?.parse::<pid_t>().ok()
    }

    fn verify(&self) -> Result<(), PidfileError> {
        let current_metadata = self.file.metadata()?;
        if current_metadata.ino() == self.metadata.ino()
            && current_metadata.dev() == self.metadata.dev()
        {
            Ok(())
        } else {
            Err(PidfileError::AlreadyRunning {
                pid: Pidfile::read(&self.path),
            })
        }
    }

    /// Writes the current process ID to the PID file.
    ///
    /// The file is truncated before writing.
    pub fn write(&mut self) -> Result<(), PidfileError> {
        self.file.set_len(0)?;
        let pid = unsafe { getpid() };
        write!(self.file, "{pid}")?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Closes the PID file without removing it.
    ///
    /// This function consumes the object, making it impossible
    /// to manipulated with the PID file after this function has
    /// been called.
    pub fn close(mut self) {
        if let Err(err) = self.verify() {
            warn!("Failed to verify the PID file before closing: {err}");
        }
        self.autoremove = false
    }
}

impl Drop for Pidfile {
    /// Closes the PID file and removes it.
    fn drop(&mut self) {
        if let Err(err) = self.verify() {
            warn!("Failed to verify the PID file before closing: {err}");
        } else if self.autoremove {
            if let Err(err) = remove_file(&self.path) {
                warn!("Failed to remove the PID file: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::fs::{read_to_string, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::process;
    use tempfile::tempdir;

    #[test]
    fn create_file() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.path().to_owned();
        pidfile_path.push("file.pid");
        let my_pid = process::id().to_string();
        {
            let mut pidfile = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
                .expect("Failed to create PID file");
            println!("pidfile_path = {pidfile_path:?}");
            assert!(pidfile_path.is_file());
            pidfile.write().expect("Failed to write PID file");

            let contents = read_to_string(pidfile_path.as_path()).expect("Can’t read PID file");
            assert_eq!(my_pid, contents);
        }

        assert!(!pidfile_path.is_file(), "PID file should have disappeared");
    }

    #[test]
    fn close_file() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.path().to_owned();
        pidfile_path.push("file.pid");
        let my_pid = process::id().to_string();
        {
            let mut pidfile = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
                .expect("Failed to create PID file");
            println!("pidfile_path = {pidfile_path:?}");
            assert!(pidfile_path.is_file());
            pidfile.write().expect("Failed to write PID file");

            let contents = read_to_string(pidfile_path.as_path()).expect("Can’t read PID file");
            assert_eq!(my_pid, contents);

            pidfile.close();
        }

        assert!(
            pidfile_path.is_file(),
            "PID file should have not disappeared"
        );
    }

    #[test]
    fn concurrent() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.path().to_owned();
        pidfile_path.push("file.pid");
        let my_pid = process::id().to_string();
        let mut pidfile = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
            .expect("Failed to create PID file");
        println!("pidfile_path = {pidfile_path:?}");
        assert!(pidfile_path.is_file(), "PID file not created?");
        pidfile.write().expect("Failed to write PID file");

        let contents = read_to_string(pidfile_path.as_path()).expect("Can’t read PID file");
        assert_eq!(my_pid, contents);

        let error = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
            .expect_err("Expected error, but got");
        assert_eq!(
            error.to_string(),
            format!("daemon already running with PID {my_pid}")
        );
        if let PidfileError::AlreadyRunning { pid } = error {
            assert_eq!(
                my_pid,
                pid.expect("No PID written?").to_string(),
                "PID different?!"
            );
        } else {
            panic!("unexpected error: {error:?}")
        }
    }
}
