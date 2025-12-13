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
#[serde(try_from = "DTGCommon")]
pub struct DTGCredential {
    /// The DTG Credential inner struct
    #[serde(flatten)]
    credential: DTGCommon,

    /// Type of the credential
    #[serde(skip)]
    type_: DTGCredentialType,
}

impl DTGCredential {
    /// get the raw credential
    pub fn credential(&self) -> &DTGCommon {
        &self.credential
    }

    /// Has this credential been signed?
    pub fn signed(&self) -> bool {
        self.credential.signed()
    }

    /// get the credential type
    pub fn type_(&self) -> DTGCredentialType {
        self.type_.clone()
    }

    /// Returns the Issuer DID
    pub fn issuer(&self) -> &str {
        self.credential.issuer()
    }

    /// Returns the Subject DID
    pub fn subject(&self) -> &str {
        self.credential.subject()
    }

    /// Returns the valid_from timestamp
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.credential.valid_from()
    }

    /// Returns the valid until timestamp
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.credential.valid_until()
    }
}

/// TDG VC Type Identifiers
#[derive(Debug, Clone)]
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

impl DTGCommon {
    /// Has this credential been signed?
    /// Returns true if a proof exists
    /// NOTE: This does NOT validate the proof itself
    pub fn signed(&self) -> bool {
        self.proof.is_some()
    }

    /// Returns the issuer DID
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the subject DID
    pub fn subject(&self) -> &str {
        match &self.credential_subject {
            CredentialSubject::Basic(subject) => &subject.id,
            CredentialSubject::Endorsement(subject) => &subject.id,
            CredentialSubject::Witness(subject) => &subject.id,
            CredentialSubject::RCard(subject) => &subject.id,
        }
    }

    /// The credential is valid from this timestamp
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }

    /// The credential is valid until this timestamp, if set
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.valid_until
    }
}

/// Helps ensure default starting point is correct
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

/// Post deserialize setup of a CredentialSubject and CredntialType
impl TryFrom<DTGCommon> for DTGCredential {
    type Error = DTGCredentialError;

    fn try_from(value: DTGCommon) -> Result<Self, Self::Error> {
        match &value.type_.as_slice().try_into()? {
            DTGCredentialType::Community => Ok(DTGCredential {
                type_: DTGCredentialType::Community,
                credential: value,
            }),
            DTGCredentialType::Personhood => Ok(DTGCredential {
                type_: DTGCredentialType::Personhood,
                credential: value,
            }),
            DTGCredentialType::Relationship => Ok(DTGCredential {
                type_: DTGCredentialType::Relationship,
                credential: value,
            }),
            DTGCredentialType::Persona => Ok(DTGCredential {
                type_: DTGCredentialType::Persona,
                credential: value,
            }),
            DTGCredentialType::Endorsement => {
                if let CredentialSubject::Endorsement { .. } = &value.credential_subject {
                    Ok(DTGCredential {
                        type_: DTGCredentialType::Endorsement,
                        credential: value,
                    })
                } else {
                    Err(DTGCredentialError::UnknownCredential)
                }
            }
            DTGCredentialType::Witness => match &value.credential_subject {
                CredentialSubject::Witness(_) => Ok(DTGCredential {
                    type_: DTGCredentialType::Witness,
                    credential: value,
                }),
                CredentialSubject::Basic(subject) => {
                    // If Wtiness CredentialSubject only contains id, it is still valid
                    Ok(DTGCredential {
                        type_: DTGCredentialType::Witness,
                        credential: DTGCommon {
                            credential_subject: CredentialSubject::Witness(
                                CredentialSubjectWitness {
                                    id: subject.id.clone(),
                                    digest: None,
                                    witness_context: None,
                                },
                            ),
                            ..value
                        },
                    })
                }
                _ => Err(DTGCredentialError::UnknownCredential),
            },
            DTGCredentialType::RCard => match &value.credential_subject {
                CredentialSubject::RCard { .. } => Ok(DTGCredential {
                    type_: DTGCredentialType::RCard,
                    credential: value,
                }),
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

    /// Credential Subject of just `id`
    /// Use by PHC, VCC, VRC and VPC
    Basic(CredentialSubjectBasic),

    /// Verifiable Witness Credential subject
    Witness(CredentialSubjectWitness),
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
    use crate::{CredentialSubject, DTGCredential, DTGCredentialType};

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

        assert!(matches!(vcc.type_, DTGCredentialType::Community));
        assert!(matches!(
            vcc.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
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

        assert!(matches!(phc.type_, DTGCredentialType::Personhood));
        assert!(matches!(
            phc.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
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

        assert!(matches!(vrc.type_, DTGCredentialType::Relationship));
        assert!(matches!(
            vrc.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
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

        assert!(matches!(vpc.type_, DTGCredentialType::Persona));
        assert!(matches!(
            vpc.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
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

        assert!(matches!(vec.type_, DTGCredentialType::Endorsement));
        assert!(matches!(
            vec.credential().credential_subject,
            CredentialSubject::Endorsement(_)
        ));
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

        assert!(matches!(vwc.type_, DTGCredentialType::Witness));
        assert!(matches!(
            vwc.credential().credential_subject,
            CredentialSubject::Witness(_)
        ));
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

        assert!(matches!(vwc.type_, DTGCredentialType::Witness));
        assert!(matches!(
            vwc.credential().credential_subject,
            CredentialSubject::Witness(_)
        ));
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

        assert!(matches!(rcard.type_, DTGCredentialType::RCard));
        assert!(matches!(
            rcard.credential().credential_subject,
            CredentialSubject::RCard(_)
        ));
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
