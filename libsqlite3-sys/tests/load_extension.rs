//! Extension loading in bundled builds follows the `omit_load_extension` feature.
#![cfg(feature = "bundled")]

use libsqlite3_sys as ffi;
use std::ffi::{CStr, CString};
use std::ptr;

/// Runs `sql` on a fresh in-memory database and returns every first-column text, or the error.
fn query(sql: &str) -> Result<Vec<String>, String> {
    let mut db = ptr::null_mut();
    let name = CString::new(":memory:").unwrap();
    assert_eq!(
        unsafe { ffi::sqlite3_open(name.as_ptr(), &mut db) },
        ffi::SQLITE_OK
    );
    let sql = CString::new(sql).unwrap();
    let mut stmt = ptr::null_mut();
    let rc = unsafe { ffi::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, ptr::null_mut()) };
    let mut result = if rc == ffi::SQLITE_OK {
        Ok(Vec::new())
    } else {
        Err(String::new())
    };
    while let Ok(rows) = &mut result {
        match unsafe { ffi::sqlite3_step(stmt) } {
            // Valid until the next step, so it is copied out at once.
            ffi::SQLITE_ROW => rows.push(
                unsafe { CStr::from_ptr(ffi::sqlite3_column_text(stmt, 0).cast()) }
                    .to_string_lossy()
                    .into_owned(),
            ),
            ffi::SQLITE_DONE => break,
            _ => result = Err(String::new()),
        }
    }
    if result.is_err() {
        // sqlite3_errmsg never returns NULL, and the text lives until the next call on `db`.
        result = Err(unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(db)) }
            .to_string_lossy()
            .into_owned());
    }
    unsafe {
        ffi::sqlite3_finalize(stmt);
        ffi::sqlite3_close(db);
    }
    result
}

#[test]
fn extension_loading_follows_its_feature() {
    let options = query("PRAGMA compile_options").unwrap();
    let has = |name: &str| options.iter().any(|o| o == name);
    let call = query("SELECT load_extension('no-such-extension')").unwrap_err();
    if cfg!(feature = "omit_load_extension") {
        assert!(has("OMIT_LOAD_EXTENSION") && !has("ENABLE_LOAD_EXTENSION"));
        assert!(call.contains("no such function"), "{call}");
    } else {
        assert!(has("ENABLE_LOAD_EXTENSION") && !has("OMIT_LOAD_EXTENSION"));
        assert!(call.contains("not authorized"), "{call}");
    }
}
