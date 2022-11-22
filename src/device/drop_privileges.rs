// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::errno_str;
use crate::device::Error;
use users;
use libc::*;

pub fn get_saved_ids() -> Result<(uid_t, gid_t), Error> {
    // Get the user name of the sudoer
    let uname = unsafe { getlogin() };
    if uname.is_null() {
        return Err(Error::DropPrivileges("NULL from getlogin".to_owned()));
    }
    let userinfo = unsafe { getpwnam(uname) };
    if userinfo.is_null() {
        return Err(Error::DropPrivileges("NULL from getpwnam".to_owned()));
    }

    // Saved group ID
    let saved_gid = unsafe { (*userinfo).pw_gid };
    // Saved user ID
    let saved_uid = unsafe { (*userinfo).pw_uid };

    Ok((saved_uid, saved_gid))
}

pub fn drop_privileges(username: Option<&str>) -> Result<(), Error> {

    let (uid, gid) = match username {
        Some(name) => {
            let user = match users::get_user_by_name(name) {
                Some(user) => user,
                None => return Err(Error::DropPrivileges("unknown user supplied to --user".to_owned())),
            };
            (user.uid(), user.primary_group_id())

        },
        None => get_saved_ids()?,
    };


    if -1 == unsafe { setgid(gid) } {
        // Set real and effective group ID
        return Err(Error::DropPrivileges(errno_str()));
    }

    if -1 == unsafe { setuid(uid) } {
        // Set  real and effective user ID
        return Err(Error::DropPrivileges(errno_str()));
    }

    // Validated we can't get sudo back again
    if unsafe { (setgid(0) != -1) || (setuid(0) != -1) } {
        Err(Error::DropPrivileges(
            "Failed to permanently drop privileges".to_owned(),
        ))
    } else {
        Ok(())
    }
}
