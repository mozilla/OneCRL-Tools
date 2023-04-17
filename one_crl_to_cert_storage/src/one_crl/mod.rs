/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use reqwest::Url;
use serde::Deserialize;
use std::convert::TryFrom;
use std::convert::TryInto;

use crate::errors::*;

const PRODUCTION: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records";
const STAGING: &str =  "https://firefox.settings.services.allizom.org/v1/buckets/security-state/collections/onecrl/records";

pub enum Environment {
    Production,
    Staging
}

impl Environment {
    pub fn valid_values() -> Vec<&'static str> {
        vec!["prod", "production", "stage", "staging"]
    }
}

impl From<&str> for Environment {

    fn from(value: &str) -> Self {
        match value {
            "production" | "prod" => Environment::Production,
            "staging" | "stage" => Environment::Staging,
            _ => panic!(format!("Programming Error: '{}' is not a valid for a OneCRL environment", value))
        }
    }
}

impl Into<Url> for Environment {
    fn into(self) -> Url {
        match self {
            Environment::Production => PRODUCTION.parse().unwrap(),
            Environment::Staging => STAGING.parse().unwrap()
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct OneCRL {
    pub data: Vec<OneCRLEntry>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum OneCRLEntry {
    Serial {
        #[serde(rename = "issuerName")]
        issuer_name: String,
        #[serde(rename = "serialNumber")]
        serial_number: String,
    },
    KeyHash {
        #[serde(rename = "subject")]
        subject_name: String,
        #[serde(rename = "pubKeyHash")]
        pub_key_hash: String,
    },
}

impl TryFrom<Environment> for OneCRL {
    type Error = Error;

    fn try_from(value: Environment) -> Result<Self> {
        let url: Url = value.into();
        url.try_into()
    }
}

impl TryFrom<String> for OneCRL {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        let url: reqwest::Url = value
            .parse()
            .chain_err(|| format!("failed to parse {} into a URL", value))?;
        url.try_into()
    }
}

impl TryFrom<Url> for OneCRL {
    type Error = Error;

    fn try_from(url: Url) -> Result<Self> {
        let url_str = url.to_string();
        Ok(reqwest::Client::new()
            .get(url)
            .header(
                reqwest::header::USER_AGENT,
                "github.com/mozilla/OneCRL-Tools/one_crl_to_cert_storage chris@chenderson.org",
            )
            .header(
                "X-Automated-Tool",
                "github.com/mozilla/OneCRL-Tools/one_crl_to_cert_storage",
            )
            .send()
            .chain_err(|| format!("GET on {} failed", url_str))?
            .json::<OneCRL>()
            .chain_err(|| format!("failed to deserialize the result from {}", url_str))?)
    }
}

impl OneCRLEntry {
    pub fn to_cert_storage(&self) -> Option<Vec<u8>> {
        match self {
            // Some entries in staging appear to have white space somewhere in them, hence the trim.
            OneCRLEntry::Serial{issuer_name, serial_number} => {
                let i = match base64::decode(issuer_name.trim()) {
                    Ok(val) => val,
                    Err(err) => {
                        println!("WARNING: the following base64 issuer name failed to decode with \
                        error: {}\n\t{}", err.to_string(), issuer_name);
                        return None;
                    }
                };
                let s = match base64::decode(serial_number.trim()) {
                    Ok(val) => val,
                    Err(err) => {
                        println!("WARNING: the following base64 serial failed to decode with \
                        error: {}\n\t{}", err.to_string(), serial_number);
                        return None;
                    }
                };
                Some(vec![vec![b'i', b's'], i, s].concat())
            },
            OneCRLEntry::KeyHash{subject_name, pub_key_hash} => {
                let s = match base64::decode(subject_name.trim()) {
                    Ok(val) => val,
                    Err(err) => {
                        println!("WARNING: the following base64 subject name failed to decode with \
                        error: {}\n\t{}", err.to_string(), subject_name);
                        return None;
                    }
                };
                let p = match base64::decode(pub_key_hash.trim()) {
                    Ok(val) => val,
                    Err(err) => {
                        println!("WARNING: the following base64 public key hash failed to decode with \
                        error: {}\n\t{}", err.to_string(), pub_key_hash);
                        return None;
                    }
                };
                Some(vec![vec![b's', b'p', b'k'], s, p].concat())
            }
        }
    }
}
