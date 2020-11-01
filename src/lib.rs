use std::ffi::{CString, NulError};
use std::fs::Permissions;
use std::io;
use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
use std::path::PathBuf;
use libc::{c_char, c_int, mode_t, pid_t};
use log::warn;
use thiserror::Error;

#[allow(non_camel_case_types)]
enum pidfn {}

extern {
    #[link_name = "pidfile_open"]
    fn bsd_pidfile_open(path: *const c_char, mode: mode_t, pidptr: *mut pid_t) -> *mut pidfn;
    #[link_name = "pidfile_write"]
    fn bsd_pidfile_write(pfh: *mut pidfn) -> c_int;
    #[link_name = "pidfile_close"]
    fn bsd_pidfile_close(pfh: *mut pidfn) -> c_int;
    #[link_name = "pidfile_remove"]
    fn bsd_pidfile_remove(pfh: *mut pidfn) -> c_int;
    #[allow(dead_code)]
    #[link_name = "pidfile_fileno"]
    fn bsd_pidfile_fileno(pfh: *mut pidfn) -> c_int;
}

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
/// [`pidfile`]: https://linux.die.net/man/3/pidfile
#[derive(Debug)]
pub struct Pidfile {
    pidfn: *mut pidfn
}

#[derive(Error, Debug)]
pub enum PidfileError {
    /// The file cannot be locked. The `pid` field contains the PID of the
    /// already running process or `None` in case it did not write
    /// its PID yet.
    #[error("daemon already running with {}", match .pid {
        Some(pid) => format!("PID {}", pid),
        None => "unknown PID".into()
    })]
    AlreadyRunning {
        pid: Option<pid_t>
    },
    /// An I/O error has occurred.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// An interior NUL byte was found in the path.
    #[error(transparent)]
    NulError(#[from] NulError),
}

impl Pidfile {
    /// Creates a new PID file and locks it.
    ///
    /// If the PID file cannot be locked, returns `PidfileError::AlreadyRunning` with
    /// a PID of the already running process, or `None` if no PID has been written to
    /// the PID file yet.
    pub fn new(path: &PathBuf, permissions: Permissions) -> Result<Pidfile, PidfileError> {
        match CString::new(path.clone().into_os_string().into_vec()) {
            Ok(c_path) => {
                let mut old_pid: pid_t = -1;
                let pidfn = unsafe {
                    bsd_pidfile_open(c_path.as_ptr(), permissions.mode(), &mut old_pid)
                };
                if !pidfn.is_null() {
                    return Ok(Pidfile {
                        pidfn: pidfn
                    });
                } else {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::AlreadyExists {
                        return Err(PidfileError::AlreadyRunning {
                            pid: if old_pid != -1 {
                                Some(old_pid)
                            } else {
                                None
                            }
                        });
                    } else {
                        Err(PidfileError::Io(err))
                    }
                }
            },
            Err(err) => {
                Err(PidfileError::NulError(err))
            }
        }
    }

    /// Writes the current process ID to the PID file.
    ///
    /// The file is truncated before writing.
    pub fn write(&self) -> Result<(), PidfileError> {
        if unsafe {
            bsd_pidfile_write(self.pidfn) == 0
        } {
            Ok(())
        } else {
            Err(PidfileError::Io(io::Error::last_os_error()))
        }
    }

    /// Close the PID file without removing it.
    ///
    /// The PID file cannot be manipulated with after this function has
    /// been called.
    pub fn close(self) {
        if unsafe {
            bsd_pidfile_close(self.pidfn) != 0
        } {
            let err = io::Error::last_os_error();
            warn!("Failed to close the PID file: {}", err);
        }
    }
}

impl Drop for Pidfile {
    fn drop(&mut self) {
        if unsafe {
            bsd_pidfile_remove(self.pidfn) != 0
        } {
            let err = io::Error::last_os_error();
            warn!("Failed to remove the PID file: {}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::fs::{Permissions, read_to_string};
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::process;
    use tempfile::tempdir;

    #[test]
    fn create_file() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.into_path();
        pidfile_path.push("file.pid");
        let my_pid = process::id().to_string();
        {
            let pidfile = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
                .expect("Failed to create PID file");
            println!("pidfile_path = {:?}", pidfile_path);
            assert_eq!(pidfile_path.is_file(), true);
            pidfile.write().expect("Failed to write PID file");

            let contents = read_to_string(pidfile_path.as_path()).expect("Can’t read PID file");
            assert_eq!(my_pid, contents);
        }

        assert_eq!(
            pidfile_path.is_file(),
            false,
            "PID file should have disappeared"
        );
    }

    #[test]
    fn close_file() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.into_path();
        pidfile_path.push("file.pid");
        let my_pid = process::id().to_string();
        {
            let pidfile = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
                .expect("Failed to create PID file");
            println!("pidfile_path = {:?}", pidfile_path);
            assert_eq!(pidfile_path.is_file(), true);
            pidfile.write().expect("Failed to write PID file");

            let contents = read_to_string(pidfile_path.as_path()).expect("Can’t read PID file");
            assert_eq!(my_pid, contents);

            pidfile.close();
        }

        assert_eq!(
            pidfile_path.is_file(),
            true,
            "PID file should have not disappeared"
        );
    }

    #[test]
    fn invalid_path() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.into_path();
        pidfile_path.push("<<non-existing>>");
        pidfile_path.push("file.pid");
        let error = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
            .expect_err("PID file shouldn’t exist, but it does");
        println!("pidfile_path = {:?}", pidfile_path);
        assert_eq!(pidfile_path.is_file(), false);
        if let PidfileError::Io(error) = error {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        } else {
            panic!("unexpected error: {:?}", error)
        }

        pidfile_path.push("\0");
        let error = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
            .expect_err("NULs should not have been accepted, but they were");
        if let PidfileError::NulError(error) = error {
            println!("expected error: {}", error);
        } else {
            panic!("unexpected error: {:?}", error)
        }
    }

    #[test]
    fn concurrent() {
        let dir = tempdir().unwrap();
        let mut pidfile_path = dir.into_path();
        pidfile_path.push("file.pid");
        let my_pid = process::id().to_string();
        let pidfile = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
            .expect("Failed to create PID file");
        println!("pidfile_path = {:?}", pidfile_path);
        assert_eq!(pidfile_path.is_file(), true, "PID file not created?");
        pidfile.write().expect("Failed to write PID file");

        let contents = read_to_string(pidfile_path.as_path()).expect("Can’t read PID file");
        assert_eq!(my_pid, contents);

        let error = Pidfile::new(&pidfile_path, Permissions::from_mode(0o600))
            .expect_err("Expected error, but got");
        assert_eq!(
            error.to_string(),
            format!("daemon already running with PID {}", my_pid)
        );
        if let PidfileError::AlreadyRunning { pid } = error {
            assert_eq!(
                my_pid,
                pid.expect("No PID written?").to_string(),
                "PID different?!"
            );
        } else {
            panic!("unexpected error: {:?}", error)
        }
    }
}
