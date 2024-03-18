use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn ptr_info<T>(ptr: *const T) {
    let address = ptr as usize;
    println!("Pointer address in hex: {:p}", ptr);

    let maps_path = Path::new("/proc/self/maps");
    let file = match File::open(maps_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open {:?}: {}", maps_path, e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let mut file_counts = HashMap::<String, i32>::new();
    let mut lines = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap_or_else(|_| String::new());
        lines.push(line.clone());

        if let Some((_, _, _, Some(file_path))) = parse_line(&line) {
            // Clone `file_path` here to store an owned String in the HashMap
            let file_path_owned = file_path.clone();
            *file_counts.entry(file_path_owned).or_insert(0) += 1;
        }
    }

    for line in &lines {
        if let Some((start, end, permissions, file_path_option)) = parse_line(line) {
            if address >= start && address <= end {
                let output = match &file_path_option {
                    Some(file_path) => {
                        // Use &file_path to borrow the String
                        let count = file_counts.get(file_path).unwrap_or(&1);
                        if *count > 1 {
                            format!("{} [{}]", file_path, count)
                        } else {
                            file_path.to_string()
                        }
                    }
                    None => "anonymous".to_string(),
                };
                println!(
                    "The pointer is in the {} section, permissions: {}, associated file: {}",
                    // Use .as_deref() to convert Option<String> to Option<&str>
                    determine_region_type(permissions, file_path_option.as_deref()),
                    permissions,
                    output
                );
                return;
            }
        }
    }

    println!("The pointer address does not belong to any known section.");
}

fn parse_line(line: &str) -> Option<(usize, usize, &str, Option<String>)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let range: Vec<&str> = parts[0].split('-').collect();
    if range.len() != 2 {
        return None;
    }

    let start = usize::from_str_radix(range[0], 16).ok()?;
    let end = usize::from_str_radix(range[1], 16).ok()?;
    let permissions = parts[1];
    // Change `file_path` to return an owned String instead of a borrowed &str
    let file_path = parts.get(5).map(|&s| s.to_owned());

    Some((start, end, permissions, file_path))
}

fn determine_region_type(permissions: &str, file_path: Option<&str>) -> &'static str {
    match (permissions, file_path) {
        (_, Some(path)) if path.contains("[stack]") => "stack",
        (_, Some(path)) if path.contains("[heap]") => "heap",
        ("r-xp", _) => "text (executable code)",
        ("rw-p", Some(path)) if path.contains(".so") => "data in shared library",
        ("r--p", Some(path)) if path.contains(".so") => "read-only data in shared library",
        ("rw-p", _) => "data or BSS",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_valid() {
        let line = "00400000-0040c000 r-xp 00000000 fc:01 123456 /usr/bin/cat";
        let parsed = parse_line(line).unwrap();
        assert_eq!(parsed.0, 0x400000); // start address
        assert_eq!(parsed.1, 0x40c000); // end address
        assert_eq!(parsed.2, "r-xp"); // permissions
        assert_eq!(parsed.3, Some("/usr/bin/cat".to_string())); // file path
    }

    #[test]
    fn test_parse_line_invalid_format() {
        let line = "invalid format line";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_determine_region_type_stack() {
        let permissions = "rw-p";
        let file_path = Some("[stack]");
        assert_eq!(determine_region_type(permissions, file_path), "stack");
    }

    #[test]
    fn test_determine_region_type_heap() {
        let permissions = "rw-p";
        let file_path = Some("[heap]");
        assert_eq!(determine_region_type(permissions, file_path), "heap");
    }

    #[test]
    fn test_determine_region_type_text_executable_code() {
        let permissions = "r-xp";
        assert_eq!(
            determine_region_type(permissions, None),
            "text (executable code)"
        );
    }

    #[test]
    fn test_determine_region_type_data_in_shared_library() {
        let permissions = "rw-p";
        let _file_path = Some("libexample.so");
        assert_eq!(
            determine_region_type(permissions, Some("libexample.so")),
            "data in shared library"
        );
    }

    #[test]
    fn test_determine_region_type_read_only_data_in_shared_library() {
        let permissions = "r--p";
        let _file_path = Some("libreadonlydata.so");
        assert_eq!(
            determine_region_type(permissions, Some("libreadonlydata.so")),
            "read-only data in shared library"
        );
    }

    #[test]
    fn test_determine_region_type_data_or_bss() {
        let permissions = "rw-p";
        assert_eq!(determine_region_type(permissions, None), "data or BSS");
    }
}
