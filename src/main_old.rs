use std::{fs, path::PathBuf};

fn main() {
    for entry in fs::read_dir("/home/rusty/maildir").unwrap() {
        let user = entry.unwrap().path();
        if user.is_dir() {
            let mut new_folder = user.clone();
            new_folder.push("new");
            fs::create_dir(new_folder).ok();
            let mut cur_folder = user.clone();
            cur_folder.push("cur");
            fs::create_dir(&cur_folder).ok();

            for folder in fs::read_dir(user).unwrap() {
                let folder = folder.unwrap().path();
                if folder.is_dir() {
                    if !["cur", "new"].contains(&folder.file_name().unwrap().to_str().unwrap()) {
                        parse_subdir(folder);
                    }
                } else {
                    let mut cur_folder = cur_folder.clone();
                    cur_folder.push(folder.file_name().unwrap());
                    fs::rename(folder, cur_folder).unwrap();
                }
            }
        }
    }
}

fn parse_subdir(mut folder: PathBuf) {
    let name = folder.file_name().unwrap().to_str().unwrap();
    let mut new_name = name
        .replace("___", " ")
        .replace("__", " ")
        .replace('_', " ")
        .trim()
        .to_string();
    if name != new_name {
        let mut new_folder = folder.clone();
        new_folder.set_file_name(&new_name);
        while new_folder.exists() {
            new_name.push('2');
            new_folder = folder.clone();
            new_folder.set_file_name(&new_name);
        }

        fs::rename(&folder, &new_folder).unwrap();
        folder = new_folder;
    }

    let mut new_folder = folder.clone();
    new_folder.push("new");
    fs::create_dir(new_folder).ok();
    let mut cur_folder = folder.clone();
    cur_folder.push("cur");
    fs::create_dir(&cur_folder).ok();

    for message in fs::read_dir(&folder).unwrap() {
        let message = message.unwrap().path();
        let mut new_message = folder.clone();
        new_message.push("cur");
        new_message.push(message.file_name().unwrap());

        if message.is_file() {
            fs::rename(message, new_message).unwrap();
        } else if !["cur", "new"].contains(&message.file_name().unwrap().to_str().unwrap()) {
            parse_subdir(message);
        }
    }
}
