use anyhow::Result;
use chrono::Utc;

use crate::ca_signer::CaSigner;
use crate::cert_reader;
use crate::store::Store;

fn green(s: &str) -> String {
    format!("\x1b[32m{s}\x1b[0m")
}

fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}

pub fn run(store: &Store) -> Result<()> {
    store.require_initialized()?;

    let now = Utc::now();
    let ca = cert_reader::read_ca_info(store)?;
    let signer = CaSigner::load(store)?;
    let crl = cert_reader::read_crl_info(store)?;
    let clients = cert_reader::list_clients(store, crl.as_ref())?;

    println!("Store: {}", store.root.display());
    println!();
    println!("Certificate Authority");
    println!("  Subject:     {}", ca.subject);
    println!("  Key type:    {}", signer.key_type());
    println!("  Created:     {}", ca.not_before.format("%Y-%m-%d"));
    let ca_days_left = (ca.not_after - now).num_days();
    println!(
        "  Expires:     {} ({} days)",
        ca.not_after.format("%Y-%m-%d"),
        ca_days_left
    );
    if ca_days_left < 0 {
        println!("  Status:      {}", red("EXPIRED"));
    } else if ca_days_left < 30 {
        println!("  Status:      {}", red("WARNING — expiring soon"));
    } else {
        println!("  Status:      {}", green("valid"));
    }

    println!();
    println!("CRL");
    match &crl {
        None => println!("  Status: {}", red("not generated (run `certies renew-crl`)")),
        Some(c) => {
            println!("  Last renewed: {}", c.last_update.format("%Y-%m-%d"));
            if let Some(next) = c.next_update {
                let days_left = (next - now).num_days();
                println!("  Next update:  {} ({} days)", next.format("%Y-%m-%d"), days_left);
                if days_left < 0 {
                    println!("  Status:       {}", red("EXPIRED — renew immediately"));
                } else if days_left < 7 {
                    println!("  Status:       {}", red("WARNING — expiring soon"));
                } else {
                    println!("  Status:       {}", green("valid"));
                }
            }
        }
    }

    println!();
    if clients.is_empty() {
        println!("Client certificates: none");
        return Ok(());
    }

    let revoked_count = clients.iter().filter(|c| c.revoked).count();
    println!(
        "Client certificates ({} total, {} revoked):",
        clients.len(),
        revoked_count
    );
    println!();

    let col = 20;
    let type_col = 8;
    println!(
        "  {:<col$} {:<col$} {:<8} {:<type_col$} {:<12} {:<12} {}",
        "Client", "Device", "Serial", "Key", "Created", "Expires", "Status"
    );
    println!("  {}", "-".repeat(95));

    for cert in &clients {
        let days_left = (cert.not_after - now).num_days();
        let status = if cert.revoked {
            red(&format!(
                "REVOKED ({})",
                cert.revoked_at
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            ))
        } else if days_left < 0 {
            red("EXPIRED")
        } else if days_left < 30 {
            red(&format!("expiring in {days_left}d"))
        } else {
            green(&format!("valid ({days_left}d left)"))
        };

        println!(
            "  {:<col$} {:<col$} #{:<7} {:<type_col$} {:<12} {:<12} {}",
            cert.client,
            cert.device,
            cert.serial,
            cert.key_type,
            cert.not_before.format("%Y-%m-%d"),
            cert.not_after.format("%Y-%m-%d"),
            status,
        );
    }

    Ok(())
}
