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
