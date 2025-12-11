# Decentralized Trust Graph (DTG) Credentials

NOTE: This is an early implementation to v0.2 of these [specifications](https://github.com/trustoverip/dtgwg-cred-tf/tree/14-revised-vrc-spec---v02).

See the [First Person Project Whitepaper](https://www.firstperson.network/white-paper)
for more information.

## Credential Type Hierarchy

All credentials inherit from the abstract `DTGCredential`.

```text
VerifiableCredential (W3C Standard)
└── DTGCredential
    ├── CommunityCredential (VCC)
    ├── PersonhoodCredential (PHC)
    ├── RelationshipCredential (VRC)
    ├── PersonaCredential (VPC)
    ├── EndorsementCredential (VEC)
    ├── WitnessCredential (VWC)
    └── RCardCredential (R-Card)
```

## Creating credentials

Each credential type has it's own `new_*()` function to create a new credential
of that type.

Example:

```Rust
let phc = DTGCredential::new_phc(issuer, subject, valid_from, valid_to);
```

The created `TDGCredential` can be Serialized to JSON using `serde_json` allowing
it to be passed into various signing libraries

## Common functions

You can deal with the raw credential as required.

```Rust
let vrc = DTGCredential::new_vrc(issuer, subject, valid_from, valid_to);

let credential = vrc.credential();
```

You can determine the credential type easily using:

```Rust
let vcc = DTGCredential::new_vcc(issuer, subject, valid_from, valid_to);

if let DTGCredentialType::VCC = vcc.type_() {
  // Good
}
```

Has this Credential been signed?

```Rust
let vcc = DTGCredential::new_vrc(issuer, subject, valid_from, valid_to);

if vcc.signed() {
  println!("Credential has been signed");
} else {
  println!("Credential has not been signed");
}
```
