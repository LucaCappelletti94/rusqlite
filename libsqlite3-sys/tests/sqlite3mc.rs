//! Contract of the `bundled-sqlite3mc` build, plus the codec probe it must fail on plain `bundled`.
#![cfg(not(any(feature = "sqlcipher", feature = "bundled-sqlcipher")))]

use libsqlite3_sys as ffi;
use std::ffi::{CStr, CString, c_int};
use std::ptr;

struct Db(*mut ffi::sqlite3);

impl Db {
    fn open(path: &str) -> Db {
        let path = CString::new(path).unwrap();
        let mut db = ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_URI;
        let rc = unsafe { ffi::sqlite3_open_v2(path.as_ptr(), &mut db, flags, ptr::null()) };
        assert_eq!(rc, ffi::SQLITE_OK, "open failed");
        Db(db)
    }

    fn error(&self, rc: c_int) -> (c_int, String) {
        // sqlite3_errmsg never returns NULL, and the text lives until the next call on `db`.
        let msg = unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(self.0)) };
        (rc, msg.to_string_lossy().into_owned())
    }

    fn exec(&self, sql: &str) -> Result<(), (c_int, String)> {
        let sql = CString::new(sql).unwrap();
        let rc = unsafe {
            ffi::sqlite3_exec(self.0, sql.as_ptr(), None, ptr::null_mut(), ptr::null_mut())
        };
        if rc == ffi::SQLITE_OK {
            Ok(())
        } else {
            Err(self.error(rc))
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        let rc = unsafe { ffi::sqlite3_close(self.0) };
        assert_eq!(rc, ffi::SQLITE_OK, "close failed");
    }
}

#[test]
fn codec_probe_distinguishes_the_builds() {
    let db = Db::open(":memory:");
    let probe = db.exec("PRAGMA cipher = 'no-such-cipher'");
    if cfg!(feature = "bundled-sqlite3mc") {
        assert!(probe.is_err(), "SQLite3MC accepted an unknown cipher");
    } else {
        assert_eq!(probe, Ok(()), "plain SQLite ignores unknown pragmas");
    }
}

#[cfg(feature = "bundled-sqlite3mc")]
mod sqlite3mc {
    use super::*;

    impl Db {
        /// Runs one statement and returns the first column of every row, NULL as `None`.
        fn query(&self, sql: &str) -> Result<Vec<Option<String>>, (c_int, String)> {
            let sql = CString::new(sql).unwrap();
            let mut stmt = ptr::null_mut();
            let rc = unsafe {
                ffi::sqlite3_prepare_v2(self.0, sql.as_ptr(), -1, &mut stmt, ptr::null_mut())
            };
            if rc != ffi::SQLITE_OK {
                return Err(self.error(rc));
            }
            let mut rows = Vec::new();
            let result = loop {
                match unsafe { ffi::sqlite3_step(stmt) } {
                    ffi::SQLITE_ROW => {
                        let text = unsafe { ffi::sqlite3_column_text(stmt, 0) };
                        rows.push((!text.is_null()).then(|| {
                            // Valid until the next step, so it is copied out at once.
                            unsafe { CStr::from_ptr(text.cast()) }
                                .to_string_lossy()
                                .into_owned()
                        }));
                    }
                    ffi::SQLITE_DONE => break Ok(rows),
                    rc => break Err(self.error(rc)),
                }
            };
            unsafe { ffi::sqlite3_finalize(stmt) };
            result
        }
    }
    use std::path::PathBuf;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const WRONG_KEY: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f";
    const MARKER: &str = "plaintext_marker_7c1e";

    fn unlock(db: &Db, hex_key: &str) {
        db.exec("PRAGMA cipher = 'chacha20'").unwrap();
        db.exec(&format!("PRAGMA key = \"x'{hex_key}'\"")).unwrap();
    }

    struct TempDb(PathBuf);

    impl TempDb {
        fn new(name: &str) -> TempDb {
            let path =
                std::env::temp_dir().join(format!("sqlite3mc-{name}-{}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            TempDb(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn versions_are_sqlite_3_53_4_and_sqlite3mc_2_5_1() {
        let lib = unsafe { CStr::from_ptr(ffi::sqlite3_libversion()) };
        assert_eq!(lib.to_str().unwrap(), "3.53.4");
        let mc = unsafe { ffi::sqlite3mc_version() };
        assert!(!mc.is_null());
        let mc = unsafe { CStr::from_ptr(mc) };
        assert_eq!(mc.to_str().unwrap(), "SQLite3 Multiple Ciphers 2.5.1");

        let db = Db::open(":memory:");
        assert_eq!(
            db.query("SELECT sqlite_version()").unwrap(),
            [Some("3.53.4".to_owned())]
        );
        assert_eq!(
            db.query("SELECT sqlite3mc_version()").unwrap(),
            [Some("SQLite3 Multiple Ciphers 2.5.1".to_owned())]
        );
    }

    #[test]
    fn compile_options_are_bundled_s_set() {
        let db = Db::open(":memory:");
        let options: Vec<String> = db
            .query("PRAGMA compile_options")
            .unwrap()
            .into_iter()
            .map(Option::unwrap)
            .collect();
        // SQLITE_CORE, HAVE_USLEEP and HAVE_LOCALTIME_R have no compile_options entry.
        let expected = [
            "DEFAULT_FOREIGN_KEYS",
            "ENABLE_API_ARMOR",
            "ENABLE_COLUMN_METADATA",
            "ENABLE_DBSTAT_VTAB",
            "ENABLE_FTS3",
            "ENABLE_FTS3_PARENTHESIS",
            "ENABLE_FTS5",
            "ENABLE_RTREE",
            "ENABLE_STAT4",
            "SOUNDEX",
            "THREADSAFE=1",
            "USE_URI",
            "HAVE_ISNAN",
        ];
        let missing: Vec<&str> = expected
            .iter()
            .copied()
            .filter(|option| !options.iter().any(|o| o == option))
            .collect();
        assert!(missing.is_empty(), "missing {missing:?} from {options:?}");
    }

    #[test]
    fn chacha20_raw_key_round_trips_and_leaks_no_plaintext() {
        let file = TempDb::new("roundtrip");
        {
            let db = Db::open(file.path());
            unlock(&db, KEY);
            assert_eq!(
                db.query("PRAGMA cipher").unwrap(),
                [Some("chacha20".to_owned())]
            );
            db.exec(&format!(
                "CREATE TABLE {MARKER}(v TEXT); INSERT INTO {MARKER} VALUES ('{MARKER}');"
            ))
            .unwrap();
        }
        {
            let db = Db::open(file.path());
            unlock(&db, KEY);
            assert_eq!(
                db.query(&format!("SELECT v FROM {MARKER}")).unwrap(),
                [Some(MARKER.to_owned())]
            );
        }
        {
            let db = Db::open(file.path());
            unlock(&db, WRONG_KEY);
            let err = db.query("SELECT count(*) FROM sqlite_schema").unwrap_err();
            assert_eq!(err.0, ffi::SQLITE_NOTADB, "{err:?}");
        }

        let bytes = std::fs::read(&file.0).unwrap();
        let page_size = 4096;
        assert!(
            !bytes.is_empty() && bytes.len().is_multiple_of(page_size),
            "{} bytes",
            bytes.len()
        );
        let marker = MARKER.as_bytes();
        for (index, page) in bytes.chunks(page_size).enumerate() {
            assert!(
                !page.windows(marker.len()).any(|w| w == marker),
                "page {} holds plaintext",
                index + 1
            );
        }
        assert!(!bytes.starts_with(b"SQLite format 3\0"));
    }

    #[cfg(feature = "session")]
    #[test]
    fn session_changeset_applies_through_apply_v3() {
        unsafe extern "C" fn abort_on_conflict(
            _ctx: *mut std::ffi::c_void,
            _conflict: c_int,
            _iter: *mut ffi::sqlite3_changeset_iter,
        ) -> c_int {
            ffi::SQLITE_CHANGESET_ABORT
        }

        let schema = "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)";
        let source = Db::open(":memory:");
        let target = Db::open(":memory:");
        source.exec(schema).unwrap();
        target.exec(schema).unwrap();

        let main = CString::new("main").unwrap();
        let mut session = ptr::null_mut();
        assert_eq!(
            unsafe { ffi::sqlite3session_create(source.0, main.as_ptr(), &mut session) },
            ffi::SQLITE_OK
        );
        assert_eq!(
            unsafe { ffi::sqlite3session_attach(session, ptr::null()) },
            ffi::SQLITE_OK
        );
        source
            .exec(
                "INSERT INTO t VALUES (1, 'one'), (2, 'two'); UPDATE t SET v = 'uno' WHERE id = 1;",
            )
            .unwrap();

        let mut len: c_int = 0;
        let mut changeset = ptr::null_mut();
        let rc = unsafe { ffi::sqlite3session_changeset(session, &mut len, &mut changeset) };
        unsafe { ffi::sqlite3session_delete(session) };
        assert_eq!(rc, ffi::SQLITE_OK);
        assert!(len > 0 && !changeset.is_null());

        let rc = unsafe {
            ffi::sqlite3changeset_apply_v3(
                target.0,
                len,
                changeset,
                None,
                Some(abort_on_conflict),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        // SQLite allocated the changeset, so SQLite frees it.
        unsafe { ffi::sqlite3_free(changeset) };
        assert_eq!(rc, ffi::SQLITE_OK, "{:?}", target.error(rc));
        assert_eq!(
            target.query("SELECT v FROM t ORDER BY id").unwrap(),
            [Some("uno".to_owned()), Some("two".to_owned())]
        );
    }

    /// Catches a `libcrypto` loaded into the process. The CI job checks the archive for OpenSSL compiled in.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_maps_no_libcrypto() {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        assert!(maps.contains("libc"), "unexpected /proc/self/maps content");
        let crypto: Vec<&str> = maps.lines().filter(|l| l.contains("libcrypto")).collect();
        assert!(crypto.is_empty(), "{crypto:?}");
    }
}
