/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// The core logic of this module was shamelessly plucked from
// https://github.com/mozkeeler/cert-storage-inspector

use rkv::{Rkv, StoreOptions, Value};
use std::path::PathBuf;

use crate::errors::*;
use crate::one_crl::OneCRL;

pub fn write(db_path: PathBuf, onecrl: OneCRL) -> Result<()> {
    let mut builder = Rkv::environment_builder();
    builder.set_max_dbs(2);
    let env = match Rkv::from_env(&db_path, builder) {
        Ok(env) => env,
        Err(err) => Err(format!("failed to capture the cert_storage database. Is Firefox running? Err: {}", err.to_string()))?
    };
    let store = match env.open_single("cert_storage", StoreOptions::create()) {
        Ok(store) => store,
        Err(err) => Err(format!("failed to open {:?}: {}", db_path, err.to_string()))?
    };
    let mut writer = match env.write() {
        Ok(writer) => writer,
        Err(err) => Err(format!("failed to open for writing {:?}: {}", db_path, err.to_string()))?
    };
    for entry in onecrl.data.into_iter() {
        if let Some(data) = entry.to_cert_storage() {
            match store.put(&mut writer, data, &Value::I64(1)) {
                Ok(_) => (),
                Err(err) => Err(format!("err: {}, failed to write the following entry to cert_storage: {:?}", err.to_string(), entry))?
            };
        }
    }
    match writer.commit() {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("failed to commit to cert_storage: {}", err.to_string()).into())
    }
}
