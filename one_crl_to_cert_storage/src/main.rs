/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod cert_storage;
mod errors;
mod one_crl;

#[macro_use]
extern crate error_chain;

use clap::{App, Arg};
use std::convert::TryInto;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::one_crl::{OneCRL, Environment};
use crate::errors::*;

fn main() -> Result<()> {
    let matches = App::new("OneCRL to Cert Storage")
        .author("Christopher Henderson, chris@chenderson.org")
        .about("Populates the given Firefox profile's cert_storage with the contents of OneCRL.")
        .after_help("Firefox must NOT be already running, as a running Firefox captures the \
        lock on the cert_storage database and will almost certainly result in an error.")
        .arg(
            Arg::with_name("env")
                .short("e")
                .long("env")
                .value_name("Production/Staging Environment")
                .takes_value(true)
                .possible_values(&Environment::valid_values())
                .default_value("prod")
                .help("Describes whether to populate cert_storage from OneCRL's production or \
                staging environment."),
        )
        .arg(
            Arg::with_name("profile")
                .takes_value(true)
                .short("p")
                .long("profile")
                .value_name("Profile Path")
                .required(true)
                .help("The profile path provided may be either the top level of a given \
        profile (E.G. Firefox/Profiles/<PROFILE>) or the specific security_state directory \
        within a profile (E.G. Firefox/Profiles/<PROFILE>/security_state).")
                .validator_os(|path| match std::fs::metadata(path) {
                    Ok(metadata) => match metadata.is_dir() {
                        true => Ok(()),
                        false => Err(OsString::from(format!(
                            "{} is not a directory",
                            path.to_string_lossy()
                        ))),
                    },
                    Err(err) => Err(OsString::from(err.to_string())),
                }),
        )
        .get_matches();
    let profile: PathBuf = PathBuf::from(matches.value_of_os("profile").unwrap());
    // Allow a little flexibility between specifying either the top level profile directory
    // or the security_state subdirectory, as both are intuitively valid.
    let profile = match profile.ends_with("security_state") {
        true => profile,
        false => {
            let p = profile.join("security_state");
            std::fs::create_dir_all(&p)?;
            p
        }
    };
    let onecrl: OneCRL = Environment::from(matches.value_of("env").unwrap()).try_into()?;
    cert_storage::write(profile, onecrl)
}
