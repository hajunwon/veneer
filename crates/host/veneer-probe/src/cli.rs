//! argv parsing + usage. v0.0.1 ships with `inspect` and `plan`.

#[derive(Default)]
pub struct Args {
    pub cmd: String,
    pub positional: Vec<String>,
}

pub fn parse(argv: &[String]) -> Args {
    let mut a = Args::default();
    if argv.len() < 2 { return a; }
    a.cmd = argv[1].clone();
    for s in &argv[2..] { a.positional.push(s.clone()); }
    a
}

pub fn usage() {
    eprintln!("veneer — minimal Type-1 hypervisor (early bring-up)");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  veneer <command> [args]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  inspect              probe host CPU: vendor, SVM/VMX support, key MSRs");
    eprintln!("  plan                 report which hypervisor backend (SVM | VMX) is viable on this host,");
    eprintln!("                       plus the memory + page-table requirements veneer would need");
    eprintln!("  profile-check <toml> validate a profile.toml against the vmlatch-compatible schema");
    eprintln!("  help, -h, --help     this help");
    eprintln!();
    eprintln!("This is a v0.0.x bring-up build — see README.md \"Status\" for what's wired up.");
}
