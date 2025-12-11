/*! Decentralized Trust Graph (DTG) Credentials
*/

use affinidi_data_integrity::DataIntegrityProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::fmt::Display;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DTGCredentialError {
    #[error("Unknown credential type")]
    UnknownCredential,
}

/// Defined DTG Credentials
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged, try_from = "DTGCommon")]
#[non_exhaustive]
pub enum DTGCredential {
    Community(DTGCommon),
    Personhood(DTGCommon),
    Relationship(DTGCommon),
    Persona(DTGCommon),
    Endorsement(DTGCommon),
    Witness(DTGCommon),
    RCard(DTGCommon),
}

/// TDG VC Type Identifiers
#[non_exhaustive]
pub enum DTGCredentialType {
    Community,
    Personhood,
    Relationship,
    Persona,
    Endorsement,
    Witness,
    RCard,
}

impl Display for DTGCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DTGCredentialType::Community => write!(f, "CommunityCredential"),
            DTGCredentialType::Personhood => write!(f, "PersonhoodCredential"),
            DTGCredentialType::Relationship => write!(f, "RelationshipCredential"),
            DTGCredentialType::Persona => write!(f, "PersonaCredential"),
            DTGCredentialType::Endorsement => write!(f, "EndorsementCredential"),
            DTGCredentialType::Witness => write!(f, "WitnessCredential"),
            DTGCredentialType::RCard => write!(f, "RCardCredential"),
        }
    }
}

const DTG_TYPES: [&str; 7] = [
    "CommunityCredential",
    "PersonhoodCredential",
    "RelationshipCredential",
    "PersonaCredential",
    "EndorsementCredential",
    "WitnessCredential",
    "RCardCredential",
];

impl TryFrom<&[String]> for DTGCredentialType {
    type Error = DTGCredentialError;

    fn try_from(types: &[String]) -> Result<Self, Self::Error> {
        if let Some(type_) = DTG_TYPES.iter().find(|t| types.contains(&t.to_string())) {
            match *type_ {
                "CommunityCredential" => Ok(DTGCredentialType::Community),
                "PersonhoodCredential" => Ok(DTGCredentialType::Personhood),
                "RelationshipCredential" => Ok(DTGCredentialType::Relationship),
                "PersonaCredential" => Ok(DTGCredentialType::Persona),
                "EndorsementCredential" => Ok(DTGCredentialType::Endorsement),
                "WitnessCredential" => Ok(DTGCredentialType::Witness),
                "RCardCredential" => Ok(DTGCredentialType::RCard),
                _ => Err(DTGCredentialError::UnknownCredential),
            }
        } else {
            Err(DTGCredentialError::UnknownCredential)
        }
    }
}

/// All DTG Credentials follow a common structure.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DTGCommon {
    /// JSON-LD links to contexts
    /// Must contain at least:
    /// https://www.w3.org/ns/credentials/v2
    /// https://firstperson.network/credentials/dtg/v1
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Credential type identifiers
    /// Must contain at least:
    /// VerifiableCredential
    /// RelationshipCredential
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// DID of the entity issuing this credential
    pub issuer: String,

    /// ISO 8601 format of when this credentials become valid from
    #[serde(serialize_with = "iso8601_format")]
    pub valid_from: DateTime<Utc>,

    /// ISO 8601 format of when this credentials become valid from
    #[serde(serialize_with = "iso8601_format_option")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<DateTime<Utc>>,

    /// Human-readable name or title of this relationship
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,

    /// Human-readable description of the credential or the relationship
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,

    /// The relationship assertion between the entities involved
    pub credential_subject: CredentialSubject,

    /// Cryptographic proof of credential authenticity
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<DataIntegrityProof>,
}

impl TryFrom<DTGCommon> for DTGCredential {
    type Error = DTGCredentialError;

    fn try_from(value: DTGCommon) -> Result<Self, Self::Error> {
        match &value.type_.as_slice().try_into()? {
            DTGCredentialType::Community => Ok(DTGCredential::Community(value)),
            DTGCredentialType::Personhood => Ok(DTGCredential::Personhood(value)),
            DTGCredentialType::Relationship => Ok(DTGCredential::Relationship(value)),
            DTGCredentialType::Persona => Ok(DTGCredential::Persona(value)),
            DTGCredentialType::Endorsement => {
                if let CredentialSubject::Endorsement { .. } = &value.credential_subject {
                    Ok(DTGCredential::Endorsement(value))
                } else {
                    Err(DTGCredentialError::UnknownCredential)
                }
            }
            DTGCredentialType::Witness => match &value.credential_subject {
                CredentialSubject::Witness { .. } => Ok(DTGCredential::Witness(value)),
                _ => Err(DTGCredentialError::UnknownCredential),
            },
            DTGCredentialType::RCard => match &value.credential_subject {
                CredentialSubject::RCard { .. } => Ok(DTGCredential::RCard(value)),
                _ => Err(DTGCredentialError::UnknownCredential),
            },
        }
    }
}

/// This correctly formats timestamps into the correct iso8601 specification for W3C Verifiable
/// Credentials
fn iso8601_format<S>(timestamp: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(
        timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .as_str(),
    )
}

fn iso8601_format_option<S>(timestamp: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(timestamp) = timestamp {
        s.serialize_str(
            timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                .as_str(),
        )
    } else {
        s.serialize_none()
    }
}

// ****************************************************************************
// Credential Subject types
// ****************************************************************************

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSubject {
    Endorsement(CredentialSubjectEndorsement),
    RCard(CredentialSubjectRCard),
    Witness(CredentialSubjectWitness),
    Basic(CredentialSubjectBasic),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectBasic {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectEndorsement {
    pub id: String,
    pub endorsement: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectWitness {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_context: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectRCard {
    pub id: String,
    pub card: Value,
}

#[cfg(test)]
mod tests {
    use crate::{CredentialSubject, DTGCredential};

    #[test]
    fn test_vcc_deserialize() {
        let vcc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "CommunityCredential"],
                "issuer": "did:example:community",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:rDid" }
            }"#,
        ) {
            Ok(vcc) => vcc,
            Err(e) => panic!("Couldn't deserialize VCC: {}", e),
        };

        assert!(matches!(vcc, DTGCredential::Community(_)));
    }

    #[test]
    fn test_phc_deserialize() {
        let phc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "PersonhoodCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(phc) => phc,
            Err(e) => panic!("Couldn't deserialize PHC: {}", e),
        };

        assert!(matches!(phc, DTGCredential::Personhood(_)));
    }

    #[test]
    fn test_vrc_deserialize() {
        let vrc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "RelationshipCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(phc) => phc,
            Err(e) => panic!("Couldn't deserialize VRC: {}", e),
        };

        assert!(matches!(vrc, DTGCredential::Relationship(_)));
    }

    #[test]
    fn test_vpc_deserialize() {
        let vpc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "PersonaCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vpc) => vpc,
            Err(e) => panic!("Couldn't deserialize VPC: {}", e),
        };

        assert!(matches!(vpc, DTGCredential::Persona(_)));
    }

    #[test]
    fn test_vec_deserialize() {
        let vec: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "EndorsementCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "endorsement": {} }
            }"#,
        ) {
            Ok(vec) => vec,
            Err(e) => panic!("Couldn't deserialize VEC: {}", e),
        };

        assert!(matches!(vec, DTGCredential::Endorsement(_)));
    }

    #[test]
    fn test_vec_bad_deserialize() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "EndorsementCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "other": [] }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(_) => {
                // Good
            }
        };
    }

    #[test]
    fn test_vwc_simple_deserialize() {
        let vwc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vwc) => vwc,
            Err(e) => panic!("Couldn't deserialize VWC: {}", e),
        };

        assert!(matches!(vwc, DTGCredential::Witness(_)));
    }

    #[test]
    fn test_vwc_full_deserialize() {
        let vwc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "digest": "abcdf", "witnessContext": {} }
            }"#,
        ) {
            Ok(vwc) => vwc,
            Err(e) => panic!("Couldn't deserialize VWC: {}", e),
        };

        assert!(matches!(vwc, DTGCredential::Witness(_)));
        if let DTGCredential::Witness(common) = vwc
            && let CredentialSubject::Witness { .. } = common.credential_subject
        {
            // good
        } else {
            panic!("CredentialSubject is not of type Witness")
        }
    }

    #[test]
    fn test_vwc_bad_deserialize() {
        if serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "digest": "abcdf", "wrongContext": {}  }
            }"#,
        ).is_ok() {
            panic!("Should have failed due to wrong CredentialSubject!");
        }
    }

    #[test]
    fn test_rcard_simple_deserialize() {
        let rcard: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "RCardCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "card": [] }
            }"#,
        ) {
            Ok(rcard) => rcard,
            Err(e) => panic!("Couldn't deserialize R-Card: {}", e),
        };

        assert!(matches!(rcard, DTGCredential::RCard(_)));
    }

    #[test]
    fn test_rcard_bad_deserialize() {
        if serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "RCardCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid"  }
            }"#,
        )
        .is_ok()
        {
            panic!("Should have failed due to wrong CredentialSubject!");
        }
    }
    #[test]
    fn test_deserialize_unknown() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "UnknownCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(e) => {
                if e.to_string() == "Unknown credential type" {
                    // test passed
                } else {
                    panic!("Wrong error type returned");
                }
            }
        };
    }

    #[test]
    fn test_deserialize_mismatched_credential_subject() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": [],
                "type": ["VerifiableCredential", "DTGCredential",  "EndorsementCredential"],
                "issuer": "did:example:governmentAgencyPhcDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(e) => {
                if e.to_string() == "Unknown credential type" {
                    // test passed
                } else {
                    panic!("Wrong error type returned");
                }
            }
        };
    }
}
