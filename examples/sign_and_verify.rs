//! This example shows a how to:
//! 1. Create a credential
//! 2. Sign the credential
//! 3. Verify the credential
//!
//! This example uses the Affinidi Trust Development Kit (TDK) to demonstrate the process of
//! signing and verifying a credential.

use affinidi_tdk::{
    TDK,
    common::config::TDKConfigBuilder,
    dids::{DID, KeyType},
};
use anyhow::Result;
use chrono::Utc;
use dtg_credentials::{DTGCommon, DTGCredential};

#[tokio::main]
async fn main() -> Result<()> {
    // Instantiate the TDK
    // No environment needs to be loaded as this exmaple is ephemeral
    let tdk = TDK::new(
        TDKConfigBuilder::new()
            .with_load_environment(false)
            .build()?,
        None,
    )
    .await?;
    println!("TDK Instantiated");

    // Create a simple DID to represent the issuer
    let (issuer_did, issuer_secret) = DID::generate_did_key(KeyType::Ed25519)?;
    println!("Created issuer DID and Secrets: {issuer_did}");

    // Create a Personhood Credential (PHC)
    let mut phc = DTGCredential::new_phc(
        issuer_did.clone(),
        "did:example:subject".to_string(),
        Utc::now(),
        None,
    );
    println!(
        "Created unsigned Personhood Credential:\n{}",
        serde_json::to_string_pretty(&phc).unwrap()
    );
    println!();

    // Sign the PHC Credential using the issuer's Secret
    let proof = phc.sign(&issuer_secret, None)?;
    println!(
        "Signed the PHC:\n {}",
        serde_json::to_string_pretty(&phc.credential().proof).unwrap()
    );
    println!();

    // verify the PHC Credential
    let unsigned_phc = DTGCommon {
        proof: None,
        ..phc.credential().clone()
    };
    tdk.verify_data(&unsigned_phc, None, &proof).await?;
    println!("Successfully verified the Personhood Credential");
    println!(
        "Full Credential:\n{}",
        serde_json::to_string_pretty(&phc).unwrap()
    );
    println!();

    Ok(())
}
