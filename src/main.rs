use std::error::Error;
use iptables::IPTables;
use tokio::{signal, select};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use anyhow::Result;

fn install_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    ipt.new_chain("mangle", "DPIBREAK")?;
    ipt.insert("mangle", "PREROUTING", "-j DPIBREAK", 1)?;
    ipt.append("mangle", "DPIBREAK",
               "-p tcp --dport 443 -j NFQUEUE --queue-num 0 --queue-bypass")?;
    Ok(())
}

fn cleanup_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    _ = ipt.delete("mangle", "PREROUTING", "-j DPIBREAK");
    _ = ipt.flush_chain("mangle", "DPIBREAK");
    _ = ipt.delete_chain("mangle", "DPIBREAK");

    Ok(())
}

fn handle_packet(msg: &mut nfq::Message) -> Result<()> {
    // TODO
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    _ = cleanup_rules(&ipt); // in case bad exit without cleanup
    install_rules(&ipt)?;

    let mut q = nfq::Queue::open()?;
    q.bind(0)?;
    let raw_fd: RawFd = q.as_raw_fd();
    let async_q = AsyncFd::new(raw_fd)?;

    loop {
        select! {
            _ = signal::ctrl_c() => {
                break;
            }

            res = async_q.readable() => {
                _ = res?;
                loop {
                    match q.recv() {
                        Ok(mut msg) => {
                            handle_packet(&mut msg)?;
                            q.verdict(msg)?;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    };

    q.unbind(0)?;
    cleanup_rules(&ipt)?;
    Ok(())
}
