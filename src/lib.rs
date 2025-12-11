/*! Decentralized Trust Graph (DTG) Credentials
*/

use affinidi_data_integrity::DataIntegrityProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::fmt::Display;
use thiserror::Error;

pub mod create;

/// Errors related to DTG Credentials
#[derive(Error, Debug)]
pub enum DTGCredentialError {
    #[error("Unknown credential type")]
    UnknownCredential,
}

/// Defined DTG Credentials
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DTGCredential {
    #[serde(flatten)]
    credential: Credential,
}

impl DTGCredential {
    /// get the raw credential
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Has this credential been signed?
    pub fn signed(&self) -> bool {
        self.credential.signed()
    }

    /// get the credential type
    pub fn type_(&self) -> DTGCredentialType {
        match &self.credential {
            Credential::Community(_) => DTGCredentialType::Community,
            Credential::Personhood(_) => DTGCredentialType::Personhood,
            Credential::Relationship(_) => DTGCredentialType::Relationship,
            Credential::Persona(_) => DTGCredentialType::Persona,
            Credential::Endorsement(_) => DTGCredentialType::Endorsement,
            Credential::Witness(_) => DTGCredentialType::Witness,
            Credential::RCard(_) => DTGCredentialType::RCard,
        }
    }
}

/// Inner credential type for [DTGCredential]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged, try_from = "DTGCommon")]
#[non_exhaustive]
pub enum Credential {
    Community(DTGCommon),
    Personhood(DTGCommon),
    Relationship(DTGCommon),
    Persona(DTGCommon),
    Endorsement(DTGCommon),
    Witness(DTGCommon),
    RCard(DTGCommon),
}

impl Credential {
    /// Has this credential been signed?
    pub fn signed(&self) -> bool {
        match self {
            Credential::Community(common)
            | Credential::Personhood(common)
            | Credential::Relationship(common)
            | Credential::Persona(common)
            | Credential::Endorsement(common)
            | Credential::Witness(common)
            | Credential::RCard(common) => common.proof.is_some(),
        }
    }
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

/// This helps with matching the right credential type to the [DTGCredentialType]
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
    /// DTGCredential
    /// VerifiableCredential
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// DID of the entity issuing this credential
    pub issuer: String,

    /// ISO 8601 format of when this credentials become valid from
    #[serde(serialize_with = "iso8601_format")]
    pub valid_from: DateTime<Utc>,

    /// ISO 8601 format of when these credentials are valid to
    #[serde(serialize_with = "iso8601_format_option")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<DateTime<Utc>>,

    /// The assertion between the entities involved
    pub credential_subject: CredentialSubject,

    /// Cryptographic proof of credential authenticity
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<DataIntegrityProof>,
}

impl Default for DTGCommon {
    fn default() -> Self {
        DTGCommon {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://firstperson.network/credentials/dtg/v1".to_string(),
            ],
            type_: vec![
                "VerifiableCredential".to_string(),
                "DTGCredential".to_string(),
            ],
            issuer: String::new(),
            valid_from: Utc::now(),
            valid_until: None,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic {
                id: String::new(),
            }),
            proof: None,
        }
    }
}

impl TryFrom<DTGCommon> for Credential {
    type Error = DTGCredentialError;

    fn try_from(value: DTGCommon) -> Result<Self, Self::Error> {
        match &value.type_.as_slice().try_into()? {
            DTGCredentialType::Community => Ok(Credential::Community(value)),
            DTGCredentialType::Personhood => Ok(Credential::Personhood(value)),
            DTGCredentialType::Relationship => Ok(Credential::Relationship(value)),
            DTGCredentialType::Persona => Ok(Credential::Persona(value)),
            DTGCredentialType::Endorsement => {
                if let CredentialSubject::Endorsement { .. } = &value.credential_subject {
                    Ok(Credential::Endorsement(value))
                } else {
                    Err(DTGCredentialError::UnknownCredential)
                }
            }
            DTGCredentialType::Witness => match &value.credential_subject {
                CredentialSubject::Witness { .. } => Ok(Credential::Witness(value)),
                _ => Err(DTGCredentialError::UnknownCredential),
            },
            DTGCredentialType::RCard => match &value.credential_subject {
                CredentialSubject::RCard { .. } => Ok(Credential::RCard(value)),
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
// NOTE: The DTG credential spec overloads the JSON attributes for different credential payloads.
// The following enum will map the credential subject schema to correct Struct type

/// This represents all possible credential subjects
/// The order of the enum is important as it will match on first match
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSubject {
    /// Verifiable Endorsement Credential subject
    Endorsement(CredentialSubjectEndorsement),

    /// R-Card Credential subject
    RCard(CredentialSubjectRCard),

    /// Verifiable Witness Credential subject
    Witness(CredentialSubjectWitness),

    /// Credential Subject of just `id`
    /// Use by PHC, VCC, VRC and VPC
    Basic(CredentialSubjectBasic),
}

/// id of the credential subject only
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectBasic {
    pub id: String,
}

/// Endorsement Credential subject
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectEndorsement {
    pub id: String,
    /// There is no spec for the endorsement content, so we use a generic JSON value
    pub endorsement: Value,
}

/// Witness Credential subject
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectWitness {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// There is no spec for the witness context content, so we use a generic JSON value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_context: Option<Value>,
}

/// R-Card Credential subject
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectRCard {
    pub id: String,

    /// JCard spec, generic JSON value
    pub card: Value,
}

#[cfg(test)]
mod tests {
    use crate::{Credential, CredentialSubject};

    #[test]
    fn test_vcc_deserialize() {
        let vcc: Credential = match serde_json::from_str(
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

        assert!(matches!(vcc, Credential::Community(_)));
    }

    #[test]
    fn test_phc_deserialize() {
        let phc: Credential = match serde_json::from_str(
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

        assert!(matches!(phc, Credential::Personhood(_)));
    }

    #[test]
    fn test_vrc_deserialize() {
        let vrc: Credential = match serde_json::from_str(
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

        assert!(matches!(vrc, Credential::Relationship(_)));
    }

    #[test]
    fn test_vpc_deserialize() {
        let vpc: Credential = match serde_json::from_str(
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

        assert!(matches!(vpc, Credential::Persona(_)));
    }

    #[test]
    fn test_vec_deserialize() {
        let vec: Credential = match serde_json::from_str(
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

        assert!(matches!(vec, Credential::Endorsement(_)));
    }

    #[test]
    fn test_vec_bad_deserialize() {
        match serde_json::from_str::<Credential>(
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
        let vwc: Credential = match serde_json::from_str(
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

        assert!(matches!(vwc, Credential::Witness(_)));
    }

    #[test]
    fn test_vwc_full_deserialize() {
        let vwc: Credential = match serde_json::from_str(
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

        assert!(matches!(vwc, Credential::Witness(_)));
        if let Credential::Witness(common) = vwc
            && let CredentialSubject::Witness { .. } = common.credential_subject
        {
            // good
        } else {
            panic!("CredentialSubject is not of type Witness")
        }
    }

    #[test]
    fn test_vwc_bad_deserialize() {
        if serde_json::from_str::<Credential>(
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
        let rcard: Credential = match serde_json::from_str(
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

        assert!(matches!(rcard, Credential::RCard(_)));
    }

    #[test]
    fn test_rcard_bad_deserialize() {
        if serde_json::from_str::<Credential>(
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
        match serde_json::from_str::<Credential>(
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
        match serde_json::from_str::<Credential>(
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
