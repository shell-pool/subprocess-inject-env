use std::{
    process::Command,
    thread,
    fs,
    path::{PathBuf, Path},
    io::Write,
    ffi::CString,
    os::unix::net::UnixStream,
    time,
};

use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use rand::{Rng, SeedableRng};

macro_rules! cerr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

const PASSWORD : &str = "SUBPROCESS_INJECT_ENV__ARG__PASSWORD";
const PASSWORD_LEN: usize = 32;

const CONTROL_SOCK: &str = "SUBPROCESS_INJECT_ENV__ARG__CONTROL_SOCK";

/// Errors encountered while setting up the environment injector.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// An opaque error with a useful debugging message but
    /// which callers should not dispatch on.
    Err {
        msg: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Error::Err { msg } => write!(f, "{}", msg)?,
            _ => write!(f, "{:?}", self)?,
        }

        Ok(())
    }
}

impl std::error::Error for Error {}

/// A handle that can be used to inject environment variables
/// into a running subprocess.
pub struct EnvInjector {
    _shim_so: ShimSo,
    control_sock: PathBuf,
    password: String,
}

impl EnvInjector {
    /// Create a new environment injector, mutating the given command
    /// to set up the communication required.
    pub fn new(cmd: &mut Command) -> Result<Self, Error> {
        let rng = rand::rngs::StdRng::from_entropy();
        let password: String = rng.sample_iter(&rand::distributions::Alphanumeric)
            .take(PASSWORD_LEN).map(char::from).collect();

        let shim_so = ShimSo::new()?;

        cmd.env("LD_PRELOAD", shim_so.path());

        let mut control_sock = PathBuf::from(shim_so.dir.path());
        control_sock.push("control.socket");
        cmd.env(CONTROL_SOCK, &control_sock);

        cmd.env(PASSWORD, password.as_str());

        Ok(EnvInjector {
            _shim_so: shim_so,
            control_sock,
            password,
        })
    }

    /// Call setenv in the child process.
    pub fn setenv(&self, key: &str, value: &str) -> Result<(), Error> {
        // The user might call the shim immediately after launching the program,
        // in which case the control socket might not be up yet. Use an
        // exponential backoff to poll until the control socket comes up.
        let mut stream = None;
        // sum(10*(2**x) for x in range(9)) = 5110 ms = ~5 s of max wait
        let mut sleep_dur = time::Duration::from_millis(10);
        for _ in 0..9 {
            stream = match UnixStream::connect(&self.control_sock) {
                Ok(s) => Some(s),
                Err(_) => {
                    thread::sleep(sleep_dur);
                    sleep_dur *= 2;
                    continue;
                }
            };
            break;
        }
        let mut stream = match stream {
            Some(s) => s,
            None => return Err(cerr!("could not dial control socket")),
        };

        assert!(self.password.as_bytes().len() == PASSWORD_LEN);
        stream.write_all(self.password.as_bytes())
            .map_err(|e| cerr!("writing password: {:?}", e))?;

        let c_key = CString::new(key)
            .map_err(|e| cerr!("converting key to cstr: {:?}", e))?;
        let c_value = CString::new(value)
            .map_err(|e| cerr!("converting value to cstr: {:?}", e))?;

        stream.write_i32::<NativeEndian>(c_key.as_bytes().len() as i32)
            .map_err(|e| cerr!("writing key length: {:?}", e))?;
        stream.write_i32::<NativeEndian>(c_value.as_bytes().len() as i32)
            .map_err(|e| cerr!("writing value length: {:?}", e))?;
        stream.write_all(key.as_bytes())
            .map_err(|e| cerr!("writing key: {:?}", e))?;
        stream.write_all(value.as_bytes())
            .map_err(|e| cerr!("writing value: {:?}", e))?;

        let ret = stream.read_i32::<NativeEndian>()
            .map_err(|e| cerr!("reading ret: {:?}", e))?;
        if ret != 0 {
            return Err(cerr!("setting env: {:?}", nix::errno::Errno::from_raw(ret)));
        }

        Ok(())
    }
}

/// A handle to the shim .so file. It is normally stored as embedded data in the
/// rlib, but for the life of one of these handles it gets written out to a tmp file.
/// The shim file gets cleaned up when this handle falls out of scope.
#[derive(Debug)]
struct ShimSo {
    dir: tempfile::TempDir,
    path: PathBuf,
}

impl ShimSo {
    fn new() -> Result<Self, Error> {
        let overlay_blob = include_bytes!(concat!(env!("OUT_DIR"), "/env_shim.so"));

        let dir = tempfile::TempDir::with_prefix("subprocess_inject_env_shim")
            .map_err(|e| cerr!("making tmp env_shim.so dir: {}", e))?;
        let mut path = PathBuf::from(dir.path());
        path.push("env_shim.so");

        let mut overlay_file =
            fs::File::create(&path).map_err(|e| cerr!("making env_shim.so: {}", e))?;
        overlay_file
            .write_all(overlay_blob)
            .map_err(|e| cerr!("writing env_shim.so: {}", e))?;

        Ok(ShimSo { dir, path })
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}
