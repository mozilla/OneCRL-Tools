/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::From;

error_chain! {
    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);

    }
}

impl std::convert::From<rkv::StoreError> for Error {
    fn from(err: rkv::StoreError) -> Self {
        format!("{:?}", err).into()
    }
}
