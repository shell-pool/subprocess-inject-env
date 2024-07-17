use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{anyhow, Context};
use subprocess_inject_env::EnvInjector;

fn main() -> anyhow::Result<()> {
    let mut cmd = Command::new("bash");
    cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::piped())
        .env("SOME_ENV_VAR", "initial_value");

    // Register the injector with your command
    // before spawning it.
    let env_injector = EnvInjector::new(&mut cmd)
        .context("creating injector")?;

    let mut child_proc = cmd.spawn()?;
    let mut child_stdin = child_proc.stdin.take()
        .ok_or(anyhow!("expect a stdin pipe"))?;

    child_stdin.write_all("echo \"initial:${SOME_ENV_VAR}\"\n".as_bytes())?;

    env_injector.setenv("SOME_ENV_VAR", "injected_value")
        .context("injecting new env var value")?;

    child_stdin.write_all("echo \"injected:${SOME_ENV_VAR}\"\n".as_bytes())?;

    child_stdin.write_all("exit\n".as_bytes())?;

    child_proc.wait()?;
    Ok(())
}
