/*!
*   Builder methods for creating new entities.
*/

use crate::{
    CredentialSubject, CredentialSubjectBasic, CredentialSubjectEndorsement,
    CredentialSubjectRCard, CredentialSubjectWitness, DTGCommon, DTGCredential, DTGCredentialType,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

impl DTGCredential {
    /// Creates a new Verified Community Credential (VCC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vcc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vcc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vcc.type_.push(DTGCredentialType::Community.to_string());

        DTGCredential {
            credential: vcc,
            type_: DTGCredentialType::Community,
        }
    }

    /// Creates a new Personhood Credential (PHC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_phc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut phc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        phc.type_.push(DTGCredentialType::Personhood.to_string());

        DTGCredential {
            credential: phc,
            type_: DTGCredentialType::Personhood,
        }
    }

    /// Creates a new Verified Relationship Credential (VRC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vrc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vrc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vrc.type_.push(DTGCredentialType::Relationship.to_string());

        DTGCredential {
            credential: vrc,
            type_: DTGCredentialType::Relationship,
        }
    }

    /// Creates a new Verified Persona Credential (VPC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vpc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vpc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vpc.type_.push(DTGCredentialType::Persona.to_string());

        DTGCredential {
            credential: vpc,
            type_: DTGCredentialType::Persona,
        }
    }

    /// Creates a new Verified Endorsement Credential (VEC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// endorsement: The endorsement details for this credential
    pub fn new_vec(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        endorsement: Value,
    ) -> Self {
        let mut vec = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Endorsement(CredentialSubjectEndorsement {
                id: subject,
                endorsement,
            }),
            ..Default::default()
        };

        vec.type_.push(DTGCredentialType::Endorsement.to_string());

        DTGCredential {
            credential: vec,
            type_: DTGCredentialType::Endorsement,
        }
    }

    /// Creates a new Verified Witness Credential (VWC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// digest: Optional Witness cryptographic hash of the witnessed VRC (prevents misuse)
    /// witness_context: Optional Semantic context for the witness
    pub fn new_vwc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        digest: Option<String>,
        witness_context: Option<Value>,
    ) -> Self {
        let mut vwc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Witness(CredentialSubjectWitness {
                id: subject,
                digest,
                witness_context,
            }),
            ..Default::default()
        };

        vwc.type_.push(DTGCredentialType::Witness.to_string());

        DTGCredential {
            credential: vwc,
            type_: DTGCredentialType::Witness,
        }
    }

    /// Creates a new Verified RCard Credential (VWC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// card: JSON Value representing a Jcard (RFC 7095) format
    pub fn new_rcard(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        card: Value,
    ) -> Self {
        let mut rcard = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::RCard(CredentialSubjectRCard {
                id: subject,
                card,
            }),
            ..Default::default()
        };

        rcard.type_.push(DTGCredentialType::RCard.to_string());

        DTGCredential {
            credential: rcard,
            type_: DTGCredentialType::RCard,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::DTGCredential;
    use chrono::{DateTime, Utc};
    use serde_json::json;

    #[test]
    fn test_phc_serialization() {
        let phc = DTGCredential::new_phc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&phc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "PersonhoodCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vcc_serialization() {
        let vcc = DTGCredential::new_vcc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&vcc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "CommunityCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vrc_serialization() {
        let vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&vrc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "RelationshipCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vpc_serialization() {
        let vpc = DTGCredential::new_vpc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&vpc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "PersonaCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vec_serialization() {
        let vec = DTGCredential::new_vec(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            json!({
              "type": "SkillEndorsement",
              "name": "Software Development",
              "competencyLevel": "expert"
            }),
        );

        let txt = serde_json::to_string_pretty(&vec).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "EndorsementCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "endorsement": {
      "competencyLevel": "expert",
      "name": "Software Development",
      "type": "SkillEndorsement"
    }
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vwc_serialization() {
        let vwc = DTGCredential::new_vwc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            Some("sha256:test1234".to_string()),
            Some(json!({
                "event": "EthDenver 2024",
                "sessionId": "session-8822-nonce",
                "method": "in-person-proximity"
            })),
        );

        let txt = serde_json::to_string_pretty(&vwc).unwrap();

        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "WitnessCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "digest": "sha256:test1234",
    "witnessContext": {
      "event": "EthDenver 2024",
      "method": "in-person-proximity",
      "sessionId": "session-8822-nonce"
    }
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_rcard_serialization() {
        let rcard = DTGCredential::new_rcard(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            json!([
                "vcard",
                [
                    ["fn", {}, "text", "Alice Smith"],
                    ["email", {}, "text", "alice@example.com"]
                ]
            ]),
        );

        let txt = serde_json::to_string_pretty(&rcard).unwrap();

        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "RCardCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "card": [
      "vcard",
      [
        [
          "fn",
          {},
          "text",
          "Alice Smith"
        ],
        [
          "email",
          {},
          "text",
          "alice@example.com"
        ]
      ]
    ]
  }
}"#;

        assert_eq!(txt, sample);
    }
}
