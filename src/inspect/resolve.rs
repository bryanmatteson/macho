use super::ImageInfo;

/// Resolve dyld path variables (`@rpath`, `@loader_path`, `@executable_path`)
/// in a dylib install name or rpath entry.
///
/// - `@rpath/Foo.framework/Foo` is expanded by trying each rpath from
///   `image_info.rpaths` in order, returning the first candidate with `@rpath`
///   replaced. If no rpaths exist, the path is returned unchanged.
/// - `@loader_path/...` is replaced with the directory of `loader_path`.
/// - `@executable_path/...` is replaced with the directory of `executable_path`.
///
/// If the path contains no special prefix it is returned unchanged.
///
/// To obtain all possible rpath expansions, use [`resolve_all_rpaths`].
pub fn resolve_path(
    path: &str,
    image_info: &ImageInfo,
    loader_path: Option<&str>,
    executable_path: Option<&str>,
) -> String {
    if let Some(suffix) = path.strip_prefix("@rpath/") {
        if let Some(first_rpath) = image_info.rpaths.first() {
            let resolved_rpath = resolve_single_variable(first_rpath, loader_path, executable_path);
            return format!("{resolved_rpath}/{suffix}");
        }
        return path.to_string();
    }

    resolve_single_variable(path, loader_path, executable_path)
}

/// Expand `@rpath/...` against every rpath in `image_info.rpaths`, returning
/// all candidate paths. Each rpath entry is itself resolved for
/// `@loader_path` / `@executable_path` before substitution.
///
/// If `path` does not start with `@rpath/`, returns a single-element vec with
/// the result of [`resolve_path`].
///
/// Returns an empty vec only when the path starts with `@rpath/` and there are
/// no rpaths in the image.
pub fn resolve_all_rpaths(
    path: &str,
    image_info: &ImageInfo,
    loader_path: Option<&str>,
    executable_path: Option<&str>,
) -> Vec<String> {
    if let Some(suffix) = path.strip_prefix("@rpath/") {
        if image_info.rpaths.is_empty() {
            return Vec::new();
        }
        image_info
            .rpaths
            .iter()
            .map(|rpath| {
                let resolved = resolve_single_variable(rpath, loader_path, executable_path);
                format!("{resolved}/{suffix}")
            })
            .collect()
    } else {
        vec![resolve_single_variable(path, loader_path, executable_path)]
    }
}

fn resolve_single_variable(
    path: &str,
    loader_path: Option<&str>,
    executable_path: Option<&str>,
) -> String {
    if let Some(suffix) = path.strip_prefix("@loader_path/") {
        if let Some(lp) = loader_path {
            let dir = parent_dir(lp);
            return format!("{dir}/{suffix}");
        }
        return path.to_string();
    }

    if let Some(suffix) = path.strip_prefix("@executable_path/") {
        if let Some(ep) = executable_path {
            let dir = parent_dir(ep);
            return format!("{dir}/{suffix}");
        }
        return path.to_string();
    }

    path.to_string()
}

fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(pos) if pos > 0 => &path[..pos],
        Some(_) => "/",
        None => ".",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::ImageInfo;

    fn dummy_info(rpaths: Vec<String>) -> ImageInfo {
        ImageInfo {
            arch: "arm64".to_string(),
            file_type: "MH_EXECUTE".to_string(),
            uuid: None,
            image_base: 0,
            platform: None,
            source_version: None,
            install_name: None,
            linked_dylibs: Vec::new(),
            rpaths,
            target_triple: None,
        }
    }

    #[test]
    fn resolve_plain_path() {
        let info = dummy_info(Vec::new());
        let result = resolve_path("/usr/lib/libSystem.B.dylib", &info, None, None);
        assert_eq!(result, "/usr/lib/libSystem.B.dylib");
    }

    #[test]
    fn resolve_rpath_with_available_rpath() {
        let info = dummy_info(vec!["@loader_path/../Frameworks".to_string()]);
        let result = resolve_path(
            "@rpath/Foo.framework/Foo",
            &info,
            Some("/Applications/App.app/Contents/MacOS/App"),
            None,
        );
        assert_eq!(
            result,
            "/Applications/App.app/Contents/MacOS/../Frameworks/Foo.framework/Foo"
        );
    }

    #[test]
    fn resolve_rpath_without_rpaths() {
        let info = dummy_info(Vec::new());
        let result = resolve_path("@rpath/Foo.framework/Foo", &info, None, None);
        assert_eq!(result, "@rpath/Foo.framework/Foo");
    }

    #[test]
    fn resolve_loader_path() {
        let info = dummy_info(Vec::new());
        let result = resolve_path(
            "@loader_path/../lib/libfoo.dylib",
            &info,
            Some("/usr/local/bin/myapp"),
            None,
        );
        assert_eq!(result, "/usr/local/bin/../lib/libfoo.dylib");
    }

    #[test]
    fn resolve_executable_path() {
        let info = dummy_info(Vec::new());
        let result = resolve_path(
            "@executable_path/../Frameworks/Bar.framework/Bar",
            &info,
            None,
            Some("/Applications/MyApp.app/Contents/MacOS/MyApp"),
        );
        assert_eq!(
            result,
            "/Applications/MyApp.app/Contents/MacOS/../Frameworks/Bar.framework/Bar"
        );
    }

    #[test]
    fn resolve_rpath_with_plain_rpath() {
        let info = dummy_info(vec!["/opt/lib".to_string()]);
        let result = resolve_path("@rpath/libfoo.dylib", &info, None, None);
        assert_eq!(result, "/opt/lib/libfoo.dylib");
    }

    #[test]
    fn resolve_all_rpaths_multiple() {
        let info = dummy_info(vec![
            "/opt/lib".to_string(),
            "/usr/local/lib".to_string(),
            "@loader_path/../Frameworks".to_string(),
        ]);
        let result = resolve_all_rpaths(
            "@rpath/libfoo.dylib",
            &info,
            Some("/Applications/App.app/Contents/MacOS/App"),
            None,
        );
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "/opt/lib/libfoo.dylib");
        assert_eq!(result[1], "/usr/local/lib/libfoo.dylib");
        assert_eq!(
            result[2],
            "/Applications/App.app/Contents/MacOS/../Frameworks/libfoo.dylib"
        );
    }

    #[test]
    fn resolve_all_rpaths_empty() {
        let info = dummy_info(Vec::new());
        let result = resolve_all_rpaths("@rpath/libfoo.dylib", &info, None, None);
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_all_rpaths_non_rpath_path() {
        let info = dummy_info(vec!["/opt/lib".to_string()]);
        let result = resolve_all_rpaths("/usr/lib/libSystem.B.dylib", &info, None, None);
        assert_eq!(result, vec!["/usr/lib/libSystem.B.dylib"]);
    }

    #[test]
    fn resolve_rpath_with_executable_path_in_rpath() {
        let info = dummy_info(vec!["@executable_path/../Frameworks".to_string()]);
        let result = resolve_path(
            "@rpath/Foo.framework/Foo",
            &info,
            None,
            Some("/Applications/App.app/Contents/MacOS/App"),
        );
        assert_eq!(
            result,
            "/Applications/App.app/Contents/MacOS/../Frameworks/Foo.framework/Foo"
        );
    }
}
