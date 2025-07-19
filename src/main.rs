use std::error::Error;
use iptables::IPTables;
use tokio::signal;

fn install_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    ipt.new_chain("mangle", "DPIBREAK")?;
    ipt.insert("mangle", "PREROUTING", "-j DPIBREAK", 1)?;
    ipt.append("mangle", "DPIBREAK",
               "-p tcp --dport 443 -j NFQUEUE --queue-num 0 --queue-bypass")?;
    Ok(())
}

fn cleanup_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    let _ = ipt.delete("mangle", "PREROUTING", "-j DPIBREAK");
    let _ = ipt.flush_chain("mangle", "DPIBREAK");
    let _ = ipt.delete_chain("mangle", "DPIBREAK");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    let _ = cleanup_rules(&ipt); // in case bad exit without cleanup
    install_rules(&ipt)?;

    signal::ctrl_c().await?;
    let _ = cleanup_rules(&ipt);

    Ok(())
}
