//! Authenticated browser-image uploads for writable web rooms.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

pub(super) const IMAGE_UPLOAD_PATH: &str = "/__rimz/upload/image";
pub(super) const MAX_IMAGE_BYTES: u64 = 20 * 1024 * 1024;
const IMAGE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub(super) enum ImageUploadErr {
    #[error("pasted image is empty")]
    Empty,
    #[error("pasted image is {size} bytes; the limit is {limit} bytes")]
    TooLarge { size: u64, limit: u64 },
    #[error("pasted image is not PNG, JPEG, WebP, or GIF")]
    Unsupported,
    #[error("could not {action} image upload path {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("image upload directory {path} belongs to uid {found}, not uid {expected}")]
    WrongOwner {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("image upload path {path} is not a directory")]
    NotDirectory { path: PathBuf },
    #[error("image upload path {path} is not valid UTF-8")]
    NonUtf8Path { path: PathBuf },
}

pub(super) type Result<T> = std::result::Result<T, ImageUploadErr>;

#[derive(Clone, Debug)]
pub(super) struct ImageUploadStore {
    root: PathBuf,
}

impl ImageUploadStore {
    /// 准备当前用户独占的系统临时图片目录。
    pub(super) fn prepare() -> Result<Self> {
        Self::prepare_at(system_upload_root()?)
    }

    /// 校验目录边界并收紧权限，拒绝符号链接或其他用户的目录。
    fn prepare_at(root: PathBuf) -> Result<Self> {
        create_private_dir(&root)?;
        validate_private_dir(&root)?;
        Ok(Self { root })
    }

    /// 校验图片格式并以不可预测文件名原子占位后写入。
    pub(super) fn store(&self, bytes: &[u8]) -> Result<PathBuf> {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size == 0 {
            return Err(ImageUploadErr::Empty);
        }
        if size > MAX_IMAGE_BYTES {
            return Err(ImageUploadErr::TooLarge {
                size,
                limit: MAX_IMAGE_BYTES,
            });
        }
        let kind = ImageKind::detect(bytes).ok_or(ImageUploadErr::Unsupported)?;
        self.cleanup_expired_best_effort();
        let path = self
            .root
            .join(format!("{}.{}", Uuid::now_v7(), kind.extension()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|source| ImageUploadErr::Io {
            action: "create",
            path: path.clone(),
            source,
        })?;
        if let Err(source) = file.write_all(bytes) {
            let _ = fs::remove_file(&path);
            return Err(ImageUploadErr::Io {
                action: "write",
                path,
                source,
            });
        }
        Ok(path)
    }

    /// 清除过期的普通文件；清理失败不阻断本次用户粘贴。
    fn cleanup_expired_best_effort(&self) {
        let cutoff = SystemTime::now()
            .checked_sub(IMAGE_MAX_AGE)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let path = entry.path();
            let expired = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| modified < cutoff);
            if expired && let Err(err) = fs::remove_file(&path) {
                tracing::debug!(path = %path.display(), error = %err, "expired web image upload could not be removed");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageKind {
    Png,
    Jpeg,
    Webp,
    Gif,
}

impl ImageKind {
    /// 使用文件魔数识别允许的位图格式，不信任客户端 MIME。
    fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if bytes.starts_with(b"\xff\xd8\xff") {
            Some(Self::Jpeg)
        } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
            Some(Self::Webp)
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Some(Self::Gif)
        } else {
            None
        }
    }

    /// 返回与检测格式一致的安全扩展名。
    const fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Webp => "webp",
            Self::Gif => "gif",
        }
    }
}

/// 解析绝对临时根，并生成按有效用户隔离的目录名。
fn system_upload_root() -> Result<PathBuf> {
    let configured = std::env::temp_dir();
    let temp = fs::canonicalize(&configured).map_err(|source| ImageUploadErr::Io {
        action: "resolve",
        path: configured,
        source,
    })?;
    #[cfg(unix)]
    {
        Ok(temp.join(format!(
            "rimz-web-images-{}",
            nix::unistd::Uid::current().as_raw()
        )))
    }
    #[cfg(not(unix))]
    Ok(temp.join("rimz-web-images"))
}

/// 创建私有目录，已存在时交给后续校验处理。
fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(ImageUploadErr::Io {
            action: "create",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// 拒绝符号链接和跨用户目录，并固定 Unix 权限为 0700。
fn validate_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ImageUploadErr::Io {
        action: "inspect",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ImageUploadErr::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    if path.to_str().is_none() {
        return Err(ImageUploadErr::NonUtf8Path {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let expected = nix::unistd::Uid::current().as_raw();
        let found = metadata.uid();
        if found != expected {
            return Err(ImageUploadErr::WrongOwner {
                path: path.to_path_buf(),
                found,
                expected,
            });
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ImageUploadErr::Io {
                action: "secure",
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_detected_png_in_a_private_directory() {
        let temp = tempfile::tempdir().expect("temporary upload parent");
        let root = temp.path().join("uploads");
        let store = ImageUploadStore::prepare_at(root.clone()).expect("prepare image store");
        let path = store.store(b"\x89PNG\r\n\x1a\nimage").expect("store PNG");

        assert_eq!(path.parent(), Some(root.as_path()));
        assert_eq!(
            path.extension().and_then(|value| value.to_str()),
            Some("png")
        );
        assert_eq!(
            fs::read(path).expect("read stored PNG"),
            b"\x89PNG\r\n\x1a\nimage"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(root)
                    .expect("upload root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn rejects_svg_and_oversized_images() {
        let temp = tempfile::tempdir().expect("temporary upload parent");
        let store =
            ImageUploadStore::prepare_at(temp.path().join("uploads")).expect("prepare image store");

        assert!(matches!(
            store.store(b"<svg></svg>"),
            Err(ImageUploadErr::Unsupported)
        ));
        let oversized = vec![0_u8; usize::try_from(MAX_IMAGE_BYTES + 1).expect("test size")];
        assert!(matches!(
            store.store(&oversized),
            Err(ImageUploadErr::TooLarge { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_upload_root() {
        let temp = tempfile::tempdir().expect("temporary upload parent");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("create symlink target");
        let root = temp.path().join("uploads");
        std::os::unix::fs::symlink(target, &root).expect("create upload symlink");

        assert!(matches!(
            ImageUploadStore::prepare_at(root),
            Err(ImageUploadErr::NotDirectory { .. })
        ));
    }

    #[test]
    fn removes_expired_regular_files_before_storing() {
        let temp = tempfile::tempdir().expect("temporary upload parent");
        let store =
            ImageUploadStore::prepare_at(temp.path().join("uploads")).expect("prepare image store");
        let expired = store.root.join("expired.png");
        let file = fs::File::create(&expired).expect("create expired image");
        file.set_times(
            fs::FileTimes::new().set_modified(
                SystemTime::now()
                    .checked_sub(IMAGE_MAX_AGE + Duration::from_secs(1))
                    .expect("old timestamp"),
            ),
        )
        .expect("age expired image");

        store
            .store(b"\x89PNG\r\n\x1a\nnew")
            .expect("store replacement image");
        assert!(!expired.exists());
    }
}
