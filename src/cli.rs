//! The command line: the clap tree and one handler per command.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_auth::{AuthLogin, AuthMethod, AuthStatus};
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{dates, output, CliError, CommonArgs, Paged, RangeArgs, Reason};
use pk_cli_documents::{DownloadBatch, SavedDocument, SkippedDocument};
use pk_cli_http::BlockingTransport;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};
use serde_json::{json, Map, Value};

use crate::config::{self, Config, Practice};
use crate::directory::{self, Directory};
use crate::documents;
use crate::env::Environment;
use crate::export;
use crate::fhir::{self, Client};
use crate::login;
use crate::oauth;
use crate::session::{self, KeychainStore, SessionEntry, SessionIndex, TokenSet, TokenStore};
use crate::stream::{self, Header, Writer};
use crate::{unix_now, BIN, REPO, VERSION};

/// Unofficial; not affiliated with or endorsed by athenahealth. A patient's or
/// caregiver's own records from athenahealth practices, through athenahealth's
/// patient-access SMART on FHIR API. Read-only: it changes nothing at any
/// practice.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub common: CommonArgs,
    /// The config file (default: ~/.config/athena/config.json). Session and
    /// directory state live beside it.
    #[arg(long, global = true, env = "ATHENA_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Sign in, see who is signed in, sign out.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Non-secret settings: client ids, redirect ports, practice profiles.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Practice profiles, and athenahealth's directory of practices (org-list/v1).
    #[command(subcommand)]
    Orgs(OrgsCmd),
    /// The patients signed in (patient-list/v1).
    #[command(subcommand)]
    Patients(PatientsCmd),
    /// Everything a sign-in can read, as a records-stream/v1 stream.
    #[command(subcommand)]
    Records(RecordsCmd),
    /// Files: documents and report forms, fetched as Binary (documents/v1).
    #[command(subcommand)]
    Documents(DocumentsCmd),
    /// A raw read from the signed-in FHIR server: `athena api GET Patient/<id>`.
    Api(ApiCmd),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

/// Which signed-in patient a command reads.
#[derive(Args, Debug, Clone, Default)]
pub struct Select {
    /// The patient: its FHIR id or the label given at sign-in. Optional when
    /// only one is signed in.
    #[arg(long, value_name = "ID|LABEL")]
    pub patient: Option<String>,
    /// The practice profile, when the patient is signed in at more than one.
    #[arg(long, value_name = "ORG")]
    pub org: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Sign in in the browser and pick one patient record (auth-login/v1).
    Login(LoginCmd),
    /// Who is signed in, and until when (auth-status/v1). Reads the keychain,
    /// never the network.
    Status(Select),
    /// Revoke and forget a sign-in.
    Logout(LogoutCmd),
}

#[derive(Args, Debug)]
pub struct LoginCmd {
    /// The practice profile to sign in to (`athena orgs list`).
    #[arg(long, value_name = "ORG")]
    pub org: String,
    /// A short name for the patient this sign-in picks (`kid1`, `me`), so
    /// later commands can say `--patient <LABEL>`.
    #[arg(long, value_name = "LABEL")]
    pub label: Option<String>,
    /// Print the sign-in page's address instead of opening the browser.
    #[arg(long)]
    pub no_browser: bool,
    /// Minutes to wait for the sign-in.
    #[arg(long, value_name = "MINUTES", default_value_t = 5,
          value_parser = clap::value_parser!(u64).range(1..=30))]
    pub timeout: u64,
}

#[derive(Args, Debug)]
pub struct LogoutCmd {
    #[command(flatten)]
    pub select: Select,
    /// Every signed-in patient (within --org, if given).
    #[arg(long)]
    pub all: bool,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the config file's path.
    Path,
    /// Show the configuration.
    Show,
    /// Set a value.
    #[command(subcommand)]
    Set(SetCmd),
    /// Remove a value.
    #[command(subcommand)]
    Unset(UnsetCmd),
}

#[derive(Subcommand, Debug)]
pub enum SetCmd {
    /// The app's client id from athenahealth's Developer Portal, per environment.
    ClientId {
        #[arg(value_name = "CLIENT_ID")]
        id: String,
        #[arg(long, value_enum)]
        env: Environment,
    },
    /// The loopback ports registered as redirect URIs, tried in order (default 47816,47817).
    RedirectPorts {
        #[arg(value_name = "PORTS")]
        ports: String,
    },
    /// Add or change a practice profile.
    Practice(PracticeArgs),
}

#[derive(Args, Debug)]
pub struct PracticeArgs {
    /// The profile's name: 1 to 40 of a-z, 0-9 and -.
    #[arg(value_name = "SLUG")]
    pub slug: String,
    /// A display name.
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, value_enum)]
    pub env: Option<Environment>,
    /// athenaOne practice id (`orgs search` shows it).
    #[arg(long, value_name = "ID")]
    pub practice_id: Option<String>,
    /// Patient-portal brand id.
    #[arg(long, value_name = "ID")]
    pub brand_id: Option<String>,
    /// Chart sharing group id.
    #[arg(long, value_name = "ID")]
    pub csg_id: Option<String>,
    /// The practice's patient portal host, for reference.
    #[arg(long, value_name = "HOST")]
    pub portal_host: Option<String>,
    /// A FHIR base URL in full (required for --env custom).
    #[arg(long, value_name = "URL")]
    pub fhir_base: Option<String>,
    /// A client id for this profile alone.
    #[arg(long, value_name = "CLIENT_ID")]
    pub client_id: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum UnsetCmd {
    ClientId {
        #[arg(long, value_enum)]
        env: Environment,
    },
    RedirectPorts,
    Practice {
        #[arg(value_name = "SLUG")]
        slug: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum OrgsCmd {
    /// The practice profiles `--org` can name.
    #[command(visible_alias = "ls")]
    List,
    /// Search the cached directory of athenahealth practices by name, city, state, ZIP or id.
    Search {
        /// Words that must all appear in the name, city, state, ZIP or ids
        #[arg(value_name = "TEXT", required = true)]
        text: Vec<String>,
        /// The most matches to show
        #[arg(long, value_name = "N", default_value_t = 25)]
        limit: usize,
    },
    /// Download athenahealth's practice directory (about 135 MB) into the local cache.
    Refresh {
        #[arg(long, hide = true, default_value = directory::DIRECTORY_URL)]
        url: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PatientsCmd {
    /// The signed-in patients, from the local index (no keychain, no network).
    #[command(visible_alias = "ls")]
    List {
        /// Only the patients signed in at this practice profile
        #[arg(long, value_name = "ORG")]
        org: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum RecordsCmd {
    /// Write every resource the sign-in can read as records-stream/v1.
    Export(ExportCmd),
}

#[derive(Args, Debug)]
pub struct ExportCmd {
    #[command(flatten)]
    pub select: Select,
    /// Only resources updated on or after this day.
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub since: Option<String>,
    /// Write the stream to stdout, for `medrec import --from athena`.
    #[arg(long, conflicts_with = "out")]
    pub ndjson: bool,
    /// Write the stream to a new plain file in this directory: the sandbox
    /// and test servers only.
    #[arg(short = 'o', long = "out", value_name = "DIR")]
    pub out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum DocumentsCmd {
    /// The patient's documents, newest first (document-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        select: Select,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Save one document (document-download/v1), or all of them with --all
    /// (document-download-batch/v1).
    Download {
        /// The id `documents list` shows.
        #[arg(
            value_name = "ID",
            required_unless_present = "all",
            conflicts_with = "all"
        )]
        id: Option<String>,
        /// Every document, into the directory -o names.
        #[arg(long)]
        all: bool,
        /// Where to write: a file, or a directory to write into.
        #[arg(short = 'o', long = "out", value_name = "PATH")]
        out: PathBuf,
        #[command(flatten)]
        select: Select,
        #[command(flatten)]
        range: RangeArgs,
    },
}

#[derive(Args, Debug)]
pub struct ApiCmd {
    /// GET only: athena is read-only.
    #[arg(value_name = "METHOD")]
    pub method: String,
    /// A path under the FHIR base (`Patient/<id>`), or a URL on its host.
    #[arg(value_name = "PATH")]
    pub path: String,
    #[command(flatten)]
    pub select: Select,
}

/// Paths and output mode shared by every handler.
struct Ctx {
    json: bool,
    quiet: bool,
    store: ConfigStore,
}

impl Ctx {
    fn config_path(&self) -> Result<PathBuf, CliError> {
        self.store.path()
    }

    fn state_dir(&self) -> Result<PathBuf, CliError> {
        let path = self.config_path()?;
        Ok(path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")))
    }

    fn sessions_path(&self) -> Result<PathBuf, CliError> {
        Ok(self.state_dir()?.join("sessions.json"))
    }

    fn directory_path(&self) -> Result<PathBuf, CliError> {
        Ok(self.state_dir()?.join("directory.json"))
    }

    fn load(&self) -> Result<Config, CliError> {
        self.store.load()
    }

    /// Save the config readable by the owner alone: it names the household's
    /// practices.
    fn save(&self, config: &Config) -> Result<(), CliError> {
        let text = serde_json::to_string_pretty(config)
            .map_err(|e| CliError::Other(format!("encoding the config: {e}")))?;
        session::write_private(&self.config_path()?, text.as_bytes())
    }

    fn index(&self) -> Result<SessionIndex, CliError> {
        SessionIndex::load(&self.sessions_path()?)
    }

    fn note(&self, message: impl AsRef<str>) {
        if !self.quiet {
            eprintln!("{}", message.as_ref());
        }
    }
}

/// Parse, run, and exit with the contract's code.
pub fn main() {
    let cli = Cli::parse();
    let json = cli.common.json;
    match run(cli) {
        Ok(()) => {}
        Err(e) => std::process::exit(output::fail(&e, json)),
    }
}

pub fn run(cli: Cli) -> Result<(), CliError> {
    if let Some(path) = &cli.config {
        if path.as_os_str().is_empty() {
            return Err(CliError::Usage("--config needs a path".into()));
        }
    }
    let ctx = Ctx {
        json: cli.common.json,
        quiet: cli.common.quiet,
        store: ConfigStore::new(BIN).with_override(cli.config.clone()),
    };
    match cli.command {
        Command::Auth(AuthCmd::Login(args)) => auth_login(&ctx, args),
        Command::Auth(AuthCmd::Status(select)) => auth_status(&ctx, &select),
        Command::Auth(AuthCmd::Logout(args)) => auth_logout(&ctx, args),
        Command::Config(cmd) => config_cmd(&ctx, cmd),
        Command::Orgs(cmd) => orgs(&ctx, cmd),
        Command::Patients(PatientsCmd::List { org }) => patients_list(&ctx, org.as_deref()),
        Command::Records(RecordsCmd::Export(args)) => records_export(&ctx, args),
        Command::Documents(cmd) => documents_cmd(&ctx, cmd),
        Command::Api(args) => api(&ctx, args),
        Command::SelfUpdate(args) => Updater {
            repo: REPO.into(),
            binary: BIN.into(),
            target: env!("BUILD_TARGET").into(),
            current: VERSION.into(),
        }
        .run(&args, ctx.json, ctx.quiet),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            Ok(())
        }
        Command::Info => {
            info(&ctx);
            Ok(())
        }
    }
}

fn info(ctx: &Ctx) {
    let info = CliInfo::new(
        BIN,
        VERSION,
        &format!("https://github.com/{REPO}"),
        AuthInfo {
            required: true,
            method: "browser-session".into(),
            login_hint: Some("athena auth login --org <ORG> [--label <LABEL>]".into()),
        },
        &["orgs", "auth", "patients", "records", "documents", "api"],
    )
    .with_profiles(&["health-records/v1", pk_cli_documents::PROFILE]);
    // Always JSON: `info` is for machines (SPEC v1 §1.6).
    let _ = ctx;
    output::json(&serde_json::to_value(&info).unwrap_or(Value::Null));
}

// ---------------------------------------------------------------- auth

fn validate_label(label: &str) -> Result<(), CliError> {
    let ok = !label.is_empty()
        && label.len() <= 40
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(CliError::Usage(
            "--label takes 1 to 40 of letters, digits, - and _".into(),
        ))
    }
}

fn auth_login(ctx: &Ctx, args: LoginCmd) -> Result<(), CliError> {
    config::validate_slug(&args.org)?;
    if let Some(label) = &args.label {
        validate_label(label)?;
    }
    let config = ctx.load()?;
    let practice = config.practice(&args.org)?;
    let client_id = config.client_id_for(&practice)?;
    let ports = config.redirect_ports();
    let sessions_path = ctx.sessions_path()?;
    let mut index = SessionIndex::load(&sessions_path)?;

    let http = BlockingTransport::new()?;
    let lock = RefreshLock::for_binary(BIN)?;
    lock.before_signin()?;
    let org_name = practice.display_name(&args.org);
    let pending = login::prepare(
        &http,
        &login::Request {
            practice: &practice,
            org_name: &org_name,
            client_id: &client_id,
            ports: &ports,
            timeout: Duration::from_secs(args.timeout * 60),
        },
    )?;
    let url = pending.start_url();
    if args.no_browser {
        eprintln!("Open {url} in a browser to sign in to {org_name}.");
    } else {
        ctx.note(format!("Opening {url} to sign in to {org_name}."));
        if let Err(e) = login::open_browser(&url) {
            eprintln!("{e}; open {url} in a browser to sign in.");
        }
    }
    let outcome = pending.finish(&http, unix_now())?;
    let patient = outcome.tokens.patient.clone();
    let key = session::key(&args.org, &patient);
    let store = KeychainStore::new();
    lock.store_signin(|| store.set(&key, &outcome.tokens))?;

    let tokens = outcome.tokens;
    let mut entry = SessionEntry {
        org: args.org.clone(),
        patient: patient.clone(),
        label: args.label.clone(),
        relationship: outcome.relationship.map(str::to_string),
        environment: practice.environment,
        fhir_base: tokens.fhir_base.clone(),
        stored_at: dates::fmt_rfc3339(unix_now()),
        signin_expires_at: Some(dates::fmt_rfc3339(tokens.signin_expires_at())),
    };
    // A sign-in that keeps the label of another patient at this practice
    // takes it over.
    if let Some(label) = &args.label {
        for other in index.sessions.iter_mut() {
            if other.org == args.org
                && other.patient != patient
                && other.label.as_deref() == Some(label)
            {
                other.label = None;
            }
        }
    }
    index.upsert(entry.clone());
    index.save(&sessions_path)?;

    // Prove the session with one read; the record itself is discarded.
    let mut client = Client::new(&http, &store, Some(&lock), key, tokens.clone());
    let verified = match client.read(&format!("Patient/{patient}")) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "warning: the sign-in is stored, but reading the patient failed ({}): {}",
                e.code(),
                e.message()
            );
            false
        }
    };
    if client.tokens().refreshed_at != tokens.refreshed_at {
        entry.signin_expires_at = Some(dates::fmt_rfc3339(client.tokens().signin_expires_at()));
        index.upsert(entry.clone());
        index.save(&sessions_path)?;
    }

    let mut value = AuthLogin::stored(verified).to_json();
    if let Value::Object(map) = &mut value {
        map.insert("org".into(), json!(entry.org));
        map.insert("patient".into(), json!(entry.patient));
        if let Some(label) = &entry.label {
            map.insert("label".into(), json!(label));
        }
        if let Some(rel) = &entry.relationship {
            map.insert("relationship".into(), json!(rel));
        }
        map.insert("signin_expires_at".into(), json!(entry.signin_expires_at));
    }
    if ctx.json {
        output::json(&value);
    } else {
        println!(
            "Signed in to {org_name}: patient {}{}{}.",
            entry.patient,
            entry
                .label
                .as_deref()
                .map(|l| format!(" ({l})"))
                .unwrap_or_default(),
            match entry.relationship.as_deref() {
                Some("proxy") => ", as caregiver",
                _ => "",
            }
        );
        println!("Verified: {}", if verified { "yes" } else { "no" });
        if let Some(at) = &entry.signin_expires_at {
            println!("Sign in again by: {at}");
        }
    }
    Ok(())
}

fn auth_status(ctx: &Ctx, select: &Select) -> Result<(), CliError> {
    if let Some(org) = &select.org {
        config::validate_slug(org)?;
    }
    let index = ctx.index()?;
    let entries = index.matching(select.patient.as_deref(), select.org.as_deref());
    let now = unix_now();
    let store = KeychainStore::new();
    let mut sessions = Vec::new();
    let mut any_usable = false;
    for entry in entries {
        let mut row = Map::new();
        row.insert("org".into(), json!(entry.org));
        row.insert("patient".into(), json!(entry.patient));
        if let Some(label) = &entry.label {
            row.insert("label".into(), json!(label));
        }
        if let Some(rel) = &entry.relationship {
            row.insert("relationship".into(), json!(rel));
        }
        row.insert("environment".into(), json!(entry.environment));
        match store.get(&entry.key()) {
            Ok(Some(tokens)) => {
                let usable = tokens.usable(now);
                any_usable |= usable;
                row.insert("credential_in_keychain".into(), json!(true));
                row.insert("usable".into(), json!(usable));
                row.insert(
                    "refresh_token".into(),
                    json!(tokens.refresh_token.is_some()),
                );
                row.insert(
                    "access_expires_at".into(),
                    json!(dates::fmt_rfc3339(tokens.expires_at)),
                );
                row.insert(
                    "signin_expires_at".into(),
                    json!(dates::fmt_rfc3339(tokens.signin_expires_at())),
                );
            }
            Ok(None) => {
                row.insert("credential_in_keychain".into(), json!(false));
                row.insert("usable".into(), json!(false));
            }
            Err(e) => {
                row.insert("usable".into(), json!(false));
                row.insert("error".into(), json!(e.code()));
                eprintln!(
                    "warning: reading {} from the keychain failed: {}",
                    entry.key(),
                    e.message()
                );
            }
        }
        sessions.push(Value::Object(row));
    }
    let mut status = AuthStatus::new(true, any_usable, AuthMethod::BrowserSession);
    status.credential_in_keychain =
        Some(sessions.iter().any(|s| s["credential_in_keychain"] == true));
    status.session_valid = Some(any_usable);
    if ctx.json {
        let mut value = status.to_json();
        if let Value::Object(map) = &mut value {
            map.insert("sessions".into(), Value::Array(sessions));
        }
        output::json(&value);
    } else {
        status.render();
        if sessions.is_empty() {
            println!("Patients:      none signed in (athena auth login --org <ORG>)");
        } else {
            println!();
            output::table(&output::table_view(
                &sessions,
                &[
                    "org",
                    "patient",
                    "label",
                    "relationship",
                    "usable",
                    "signin_expires_at",
                ],
            ));
        }
    }
    Ok(())
}

fn auth_logout(ctx: &Ctx, args: LogoutCmd) -> Result<(), CliError> {
    if let Some(org) = &args.select.org {
        config::validate_slug(org)?;
    }
    let sessions_path = ctx.sessions_path()?;
    let mut index = SessionIndex::load(&sessions_path)?;
    let chosen: Vec<SessionEntry> = index
        .matching(args.select.patient.as_deref(), args.select.org.as_deref())
        .into_iter()
        .cloned()
        .collect();
    if chosen.is_empty() {
        return Err(CliError::NotFound("no signed-in patient matches".into())
            .with_remedy("list them with `athena patients list`"));
    }
    if chosen.len() > 1 && !args.all {
        return Err(CliError::Usage(format!(
            "{} signed-in patients match: name one with --patient (and --org), or pass --all",
            chosen.len()
        )));
    }
    let http = BlockingTransport::new()?;
    let store = KeychainStore::new();
    let mut out = Vec::new();
    for entry in chosen {
        let key = entry.key();
        let mut revoked = false;
        if let Ok(Some(tokens)) = store.get(&key) {
            revoked = revoke_all(&http, &tokens);
        }
        let found = RefreshLock::forget_for_binary(BIN, || store.delete(&key))?;
        index.remove(&entry.org, &entry.patient);
        index.save(&sessions_path)?;
        out.push(json!({
            "org": entry.org,
            "patient": entry.patient,
            "label": entry.label,
            "credential_removed": found,
            "revoked": revoked,
        }));
    }
    if ctx.json {
        output::json(&json!({"schema": "auth-logout/v1", "signed_out": out}));
    } else {
        for row in &out {
            println!(
                "Signed out {} at {}{}.",
                row["patient"].as_str().unwrap_or_default(),
                row["org"].as_str().unwrap_or_default(),
                if row["revoked"] == true {
                    " (tokens revoked)"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}

/// Revoke the refresh and access tokens, best effort.
fn revoke_all(http: &dyn crate::http::Http, tokens: &TokenSet) -> bool {
    let Some(endpoint) = &tokens.revocation_endpoint else {
        return false;
    };
    let mut ok = true;
    if let Some(rt) = &tokens.refresh_token {
        if let Err(e) = oauth::revoke(http, endpoint, &tokens.client_id, rt, "refresh_token") {
            eprintln!(
                "warning: revoking the refresh token failed: {}",
                e.message()
            );
            ok = false;
        }
    }
    if let Err(e) = oauth::revoke(
        http,
        endpoint,
        &tokens.client_id,
        &tokens.access_token,
        "access_token",
    ) {
        eprintln!("warning: revoking the access token failed: {}", e.message());
        ok = false;
    }
    ok
}

// ---------------------------------------------------------------- config

fn config_cmd(ctx: &Ctx, cmd: ConfigCmd) -> Result<(), CliError> {
    match cmd {
        ConfigCmd::Path => {
            let path = ctx.config_path()?;
            if ctx.json {
                output::json(
                    &json!({"schema": "config-path/v1", "path": path.display().to_string()}),
                );
            } else {
                println!("{}", path.display());
            }
            Ok(())
        }
        ConfigCmd::Show => {
            let config = ctx.load()?;
            let value = serde_json::to_value(&config).unwrap_or(Value::Null);
            output::emit_one(ctx.json, "config", value);
            Ok(())
        }
        ConfigCmd::Set(set) => {
            let mut config = ctx.load()?;
            let what = match set {
                SetCmd::ClientId { id, env } => {
                    config::validate_client_id(&id)?;
                    config.client_ids.set(env, Some(id));
                    format!("client id for {env}")
                }
                SetCmd::RedirectPorts { ports } => {
                    config.redirect_ports = Some(config::parse_ports(&ports)?);
                    "redirect ports".to_string()
                }
                SetCmd::Practice(args) => {
                    config::validate_slug(&args.slug)?;
                    let mut practice =
                        config
                            .practices
                            .get(&args.slug)
                            .cloned()
                            .unwrap_or_else(|| {
                                if args.slug == config::SANDBOX_ORG {
                                    Practice::sandbox()
                                } else {
                                    Practice::default()
                                }
                            });
                    if let Some(v) = args.name {
                        practice.name = Some(v);
                    }
                    if let Some(v) = args.env {
                        practice.environment = v;
                    }
                    if let Some(v) = args.practice_id {
                        practice.practice_id = Some(v);
                    }
                    if let Some(v) = args.brand_id {
                        practice.brand_id = Some(v);
                    }
                    if let Some(v) = args.csg_id {
                        practice.csg_id = Some(v);
                    }
                    if let Some(v) = args.portal_host {
                        practice.portal_host = Some(v);
                    }
                    if let Some(v) = args.fhir_base {
                        practice.fhir_base = Some(v.trim_end_matches('/').to_string());
                    }
                    if let Some(v) = args.client_id {
                        config::validate_client_id(&v)?;
                        practice.client_id = Some(v);
                    }
                    practice.validate()?;
                    config.practices.insert(args.slug.clone(), practice);
                    format!("practice `{}`", args.slug)
                }
            };
            ctx.save(&config)?;
            config_saved(ctx, &config, &what)
        }
        ConfigCmd::Unset(unset) => {
            let mut config = ctx.load()?;
            let what = match unset {
                UnsetCmd::ClientId { env } => {
                    config.client_ids.set(env, None);
                    format!("client id for {env}")
                }
                UnsetCmd::RedirectPorts => {
                    config.redirect_ports = None;
                    "redirect ports".to_string()
                }
                UnsetCmd::Practice { slug } => {
                    config::validate_slug(&slug)?;
                    if config.practices.remove(&slug).is_none() {
                        return Err(CliError::NotFound(format!(
                            "no practice profile `{slug}` is configured"
                        )));
                    }
                    format!("practice `{slug}`")
                }
            };
            ctx.save(&config)?;
            config_saved(ctx, &config, &what)
        }
    }
}

fn config_saved(ctx: &Ctx, config: &Config, what: &str) -> Result<(), CliError> {
    if ctx.json {
        let value = serde_json::to_value(config).unwrap_or(Value::Null);
        output::json(&output::tagged("config", value));
    } else {
        println!("Saved {what} to {}.", ctx.config_path()?.display());
    }
    Ok(())
}

// ---------------------------------------------------------------- orgs

fn orgs(ctx: &Ctx, cmd: OrgsCmd) -> Result<(), CliError> {
    match cmd {
        OrgsCmd::List => {
            let config = ctx.load()?;
            let items: Vec<Value> = config
                .orgs()
                .into_iter()
                .map(|org| {
                    let p = &org.practice;
                    let mut row = Map::new();
                    row.insert("id".into(), json!(org.slug));
                    row.insert("name".into(), json!(p.display_name(&org.slug)));
                    row.insert("vendor".into(), json!("athenahealth"));
                    row.insert("environment".into(), json!(p.environment));
                    for (k, v) in [
                        ("practice_id", &p.practice_id),
                        ("brand_id", &p.brand_id),
                        ("csg_id", &p.csg_id),
                        ("portal_host", &p.portal_host),
                    ] {
                        if let Some(v) = v {
                            row.insert(k.into(), json!(v));
                        }
                    }
                    if let Ok(base) = p.fhir_base() {
                        row.insert("fhir_base".into(), json!(base));
                    }
                    row.insert(
                        "client_id_configured".into(),
                        json!(config.client_id_for(p).is_ok()),
                    );
                    row.insert("builtin".into(), json!(org.builtin));
                    Value::Object(row)
                })
                .collect();
            output::emit_list(
                ctx.json,
                "org",
                items,
                &[
                    "id",
                    "name",
                    "environment",
                    "practice_id",
                    "client_id_configured",
                ],
            );
            Ok(())
        }
        OrgsCmd::Search { text, limit } => {
            let query = text.join(" ");
            if query.trim().is_empty() {
                return Err(CliError::Usage("search needs some text".into()));
            }
            let path = ctx.directory_path()?;
            let dir = Directory::load(&path)?.ok_or_else(|| {
                CliError::NotFound("athenahealth's practice directory is not downloaded yet".into())
                    .with_remedy("run `athena orgs refresh` (about 135 MB)")
            })?;
            let found = dir.search(&query);
            let total = found.len();
            let items: Vec<Value> = found
                .into_iter()
                .take(limit)
                .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                .collect();
            if ctx.json {
                let mut page = Paged::new("org", items);
                page.total = Some(total as u64);
                output::json(&serde_json::to_value(&page).unwrap_or(Value::Null));
            } else {
                output::table(&output::table_view(
                    &items,
                    &["name", "city", "state", "practice_id", "brand_id", "csg_id"],
                ));
                if total > limit {
                    eprintln!("{total} matches; showing {limit} (--limit N for more)");
                }
                ctx.note("Add one with: athena config set practice <SLUG> --practice-id <ID> --brand-id <ID> --csg-id <ID>");
            }
            Ok(())
        }
        OrgsCmd::Refresh { url } => {
            pk_cli_core::transport::require_secure_url(&url)?;
            ctx.note("Downloading athenahealth's practice directory (about 135 MB)...");
            let dir = directory::download(&url)?;
            let path = ctx.directory_path()?;
            dir.save(&path)?;
            let value = json!({
                "entries": dir.entries.len(),
                "published_at": dir.published_at,
                "fetched_at": dir.fetched_at,
                "path": path.display().to_string(),
            });
            output::emit(ctx.json, "org-directory", value, |v| {
                println!(
                    "{} practices cached in {}.",
                    v["entries"],
                    v["path"].as_str().unwrap_or_default()
                );
            });
            Ok(())
        }
    }
}

fn patients_list(ctx: &Ctx, org: Option<&str>) -> Result<(), CliError> {
    if let Some(org) = org {
        config::validate_slug(org)?;
    }
    let index = ctx.index()?;
    let items: Vec<Value> = index
        .matching(None, org)
        .into_iter()
        .map(|e| {
            let mut row = Map::new();
            row.insert("id".into(), json!(e.patient));
            row.insert("organization".into(), json!(e.org));
            if let Some(label) = &e.label {
                row.insert("label".into(), json!(label));
            }
            if let Some(rel) = &e.relationship {
                row.insert("relationship".into(), json!(rel));
            }
            row.insert("kind".into(), json!("patient"));
            row.insert("environment".into(), json!(e.environment));
            row.insert("stored_at".into(), json!(e.stored_at));
            if let Some(at) = &e.signin_expires_at {
                row.insert("signin_expires_at".into(), json!(at));
            }
            Value::Object(row)
        })
        .collect();
    output::emit_list(
        ctx.json,
        "patient",
        items,
        &[
            "id",
            "organization",
            "label",
            "relationship",
            "signin_expires_at",
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------- reads

/// The selected session's index entry and token set, before any network.
/// The indexed sign-in `select` names, without touching the keychain.
fn resolve_entry(ctx: &Ctx, select: &Select) -> Result<SessionEntry, CliError> {
    if let Some(org) = &select.org {
        config::validate_slug(org)?;
    }
    ctx.index()?
        .resolve(select.patient.as_deref(), select.org.as_deref())
}

fn open_session(ctx: &Ctx, select: &Select) -> Result<(SessionEntry, TokenSet), CliError> {
    let entry = resolve_entry(ctx, select)?;
    let tokens = KeychainStore::new().get(&entry.key())?.ok_or_else(|| {
        CliError::Auth(format!(
            "the keychain holds no sign-in for {} at {}",
            entry.patient, entry.org
        ))
        .because(Reason::NoCredential)
        .with_remedy(format!(
            "sign in again with `athena auth login --org {}`",
            entry.org
        ))
    })?;
    Ok((entry, tokens))
}

/// Keep the index's expiry in step after a command renewed the token.
fn note_renewal(ctx: &Ctx, entry: &SessionEntry, before: &TokenSet, after: &TokenSet) {
    if before.refreshed_at == after.refreshed_at {
        return;
    }
    let Ok(path) = ctx.sessions_path() else {
        return;
    };
    let Ok(mut index) = SessionIndex::load(&path) else {
        return;
    };
    let mut updated = entry.clone();
    updated.signin_expires_at = Some(dates::fmt_rfc3339(after.signin_expires_at()));
    index.upsert(updated);
    let _ = index.save(&path);
}

fn records_export(ctx: &Ctx, args: ExportCmd) -> Result<(), CliError> {
    if let Some(since) = &args.since {
        dates::parse_iso(since)?;
    }
    if !args.ndjson && args.out.is_none() {
        return Err(CliError::Usage(
            "records export writes a stream: pass --ndjson for stdout, or -o <DIR>".into(),
        ));
    }
    if args.ndjson {
        // stdout is the stream: an error goes to stderr alone, whatever
        // --json says, so stdout holds nothing that is not the stream.
        if let Err(e) = export_to_stdout(ctx, &args) {
            eprintln!("error: {e}");
            std::process::exit(e.exit_code());
        }
        return Ok(());
    }
    export_to_dir(ctx, &args)
}

fn stream_header(ctx: &Ctx, entry: &SessionEntry, since: Option<&str>) -> Result<Header, CliError> {
    let name = ctx
        .load()?
        .practices
        .get(&entry.org)
        .map(|p| p.display_name(&entry.org))
        .unwrap_or_else(|| {
            if entry.org == config::SANDBOX_ORG {
                Practice::sandbox().display_name(&entry.org)
            } else {
                entry.org.clone()
            }
        });
    Ok(Header::new(
        stream::Organization {
            id: entry.org.clone(),
            name,
            fhir_base: entry.fhir_base.clone(),
            vendor: "athenahealth",
        },
        stream::Patient {
            id: entry.patient.clone(),
            organization: entry.org.clone(),
            label: entry.label.clone(),
            relationship: entry.relationship.clone(),
            kind: "patient",
        },
        since.map(str::to_string),
        dates::fmt_rfc3339(unix_now()),
    ))
}

/// How one export ended.
enum ExportEnd<W: Write> {
    /// Before the header: nothing was written.
    Before(CliError),
    /// After the header, with every search done.
    Done(Writer<W>),
    /// After the header, cut short.
    Failed(Writer<W>, CliError),
}

/// Run one export into `out`, header to the last resource; the caller
/// writes the trailer.
fn run_export<W: Write>(ctx: &Ctx, args: &ExportCmd, out: W) -> ExportEnd<W> {
    let prepared = (|| {
        let (entry, tokens) = open_session(ctx, &args.select)?;
        let header = stream_header(ctx, &entry, args.since.as_deref())?;
        let http = BlockingTransport::new()?;
        let lock = RefreshLock::for_binary(BIN)?;
        Ok::<_, CliError>((entry, tokens, header, http, lock))
    })();
    let (entry, tokens, header, http, lock) = match prepared {
        Ok(p) => p,
        Err(e) => return ExportEnd::Before(e),
    };
    let store = KeychainStore::new();
    let mut client = Client::new(&http, &store, Some(&lock), entry.key(), tokens.clone());
    let mut w = Writer::new(out);
    if let Err(e) = w.header(&header) {
        return ExportEnd::Before(e);
    }
    let result = export::export(&mut client, &mut w, args.since.as_deref());
    note_renewal(ctx, &entry, &tokens, client.tokens());
    match result {
        Ok(()) => ExportEnd::Done(w),
        Err(e) => ExportEnd::Failed(w, e),
    }
}

fn export_to_stdout(ctx: &Ctx, args: &ExportCmd) -> Result<(), CliError> {
    let stdout = std::io::stdout();
    let out = BufWriter::new(stdout.lock());
    match run_export(ctx, args, out) {
        ExportEnd::Done(w) => {
            w.finish(dates::fmt_rfc3339(unix_now()))?;
            Ok(())
        }
        ExportEnd::Failed(w, e) => {
            w.fail(&e, dates::fmt_rfc3339(unix_now()))?;
            Err(e)
        }
        ExportEnd::Before(e) => Err(e),
    }
}

fn export_to_dir(ctx: &Ctx, args: &ExportCmd) -> Result<(), CliError> {
    let dir = args.out.clone().unwrap_or_default();
    // Resolve the session first, so a bad --patient creates no file.
    let entry = resolve_entry(ctx, &args.select)?;
    if !synthetic(&entry.fhir_base) {
        let who = entry.label.clone().unwrap_or_else(|| entry.patient.clone());
        return Err(CliError::Usage(format!(
            "-o writes records to a plain file, so it is for athenahealth's sandbox and test \
             servers only; patient {who} is at {}",
            entry.org
        ))
        .with_remedy(format!(
            "pipe them into medrec instead: `medrec import --from {BIN} --patient {who}`, \
             which runs `{BIN} records export --patient {who} --ndjson`"
        )));
    }
    create_private_dir(&dir)?;
    let stamp = dates::fmt_rfc3339(unix_now()).replace([':', '-'], "");
    let who = entry.label.clone().unwrap_or_else(|| entry.patient.clone());
    let path = dir.join(format!(
        "{}_{}_{}.ndjson",
        pk_cli_documents::fs_safe(&entry.org),
        pk_cli_documents::fs_safe(&who),
        pk_cli_documents::fs_safe(&stamp)
    ));
    let file = create_private_file(&path)?;
    let finished = match run_export(ctx, args, BufWriter::new(file)) {
        ExportEnd::Done(w) => {
            let counts = w.counts().clone();
            let skipped = w.skipped().len();
            w.finish(dates::fmt_rfc3339(unix_now()))?;
            (counts, skipped)
        }
        ExportEnd::Failed(w, e) => {
            w.fail(&e, dates::fmt_rfc3339(unix_now()))?;
            eprintln!("the stream in {} ends with complete: false", path.display());
            return Err(e);
        }
        ExportEnd::Before(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };
    let (counts, skipped) = finished;
    let total: u64 = counts.values().sum();
    let value = json!({
        "path": path.display().to_string(),
        "complete": true,
        "resources": total,
        "counts": counts,
        "skipped": skipped,
    });
    output::emit(ctx.json, "records-export", value, |v| {
        println!(
            "Wrote {} resources ({} skipped) to {}.",
            v["resources"],
            v["skipped"],
            v["path"].as_str().unwrap_or_default()
        );
    });
    Ok(())
}

/// Whether a FHIR base holds synthetic patients only: a server on this
/// machine, or athenahealth's Preview sandbox (its global base, or the
/// sandbox practices 80000 and 195900). Only these may be written to a
/// plain file with `-o`.
pub fn synthetic(fhir_base: &str) -> bool {
    let Some(origin) = crate::http::origin(fhir_base) else {
        return false;
    };
    if origin.starts_with("http://127.0.0.1:") || origin.starts_with("http://localhost:") {
        return true;
    }
    let preview = Environment::Preview
        .api_base()
        .and_then(crate::http::origin);
    if preview.as_deref() != Some(origin.as_str()) {
        return false;
    }
    let path = fhir_base[origin.len()..].trim_end_matches('/');
    path == "/fhir/r4" || path.starts_with("/80000/") || path.starts_with("/195900/")
}

fn create_private_dir(dir: &Path) -> Result<(), CliError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", dir.display())))
}

fn create_private_file(path: &Path) -> Result<std::fs::File, CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", path.display())))
}

/// Write bytes to a new file, or replace a file athena wrote before, owner-only.
fn save_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    session::write_private(path, bytes)
}

fn documents_cmd(ctx: &Ctx, cmd: DocumentsCmd) -> Result<(), CliError> {
    match cmd {
        DocumentsCmd::List { select, range } => {
            range.validate()?;
            let (entry, tokens) = open_session(ctx, &select)?;
            let http = BlockingTransport::new()?;
            let lock = RefreshLock::for_binary(BIN)?;
            let store = KeychainStore::new();
            let mut client = Client::new(&http, &store, Some(&lock), entry.key(), tokens.clone());
            let items = documents::list(&mut client, &range);
            note_renewal(ctx, &entry, &tokens, client.tokens());
            let docs: Vec<_> = items?.into_iter().map(|i| i.document).collect();
            let page = Paged::new("document", docs);
            page.emit(ctx.json);
            Ok(())
        }
        DocumentsCmd::Download {
            id,
            all,
            out,
            select,
            range,
        } => {
            range.validate()?;
            if let Some(id) = &id {
                documents::parse_id(id)?;
            }
            if all && !out.is_dir() {
                create_private_dir(&out)?;
            }
            let (entry, tokens) = open_session(ctx, &select)?;
            let http = BlockingTransport::new()?;
            let lock = RefreshLock::for_binary(BIN)?;
            let store = KeychainStore::new();
            let mut client = Client::new(&http, &store, Some(&lock), entry.key(), tokens.clone());
            let result = if all {
                download_all(ctx, &mut client, &out, &range)
            } else {
                download_one(ctx, &mut client, id.as_deref().unwrap_or_default(), &out)
            };
            note_renewal(ctx, &entry, &tokens, client.tokens());
            result
        }
    }
}

fn download_one(ctx: &Ctx, client: &mut Client<'_>, id: &str, out: &Path) -> Result<(), CliError> {
    let item = documents::find(client, id)?;
    let fetched = documents::fetch(client, &item).map_err(|f| f.error)?;
    let path = documents::target(out, &item, fetched.content_type.as_deref());
    save_file(&path, &fetched.bytes)?;
    let saved = SavedDocument::from_document(
        &item.document,
        path.display().to_string(),
        fetched.bytes.len() as u64,
    );
    if ctx.json {
        output::json(&serde_json::to_value(&saved).unwrap_or(Value::Null));
    } else {
        println!(
            "Saved {} ({} bytes) to {}.",
            saved.id, saved.bytes, saved.path
        );
    }
    Ok(())
}

fn download_all(
    ctx: &Ctx,
    client: &mut Client<'_>,
    dir: &Path,
    range: &RangeArgs,
) -> Result<(), CliError> {
    let items = documents::list(client, range)?;
    let mut saved = Vec::new();
    let mut skipped = Vec::new();
    for item in items {
        match documents::fetch(client, &item) {
            Ok(fetched) => {
                let path = dir.join(documents::file_name(&item, fetched.content_type.as_deref()));
                save_file(&path, &fetched.bytes)?;
                saved.push(SavedDocument::from_document(
                    &item.document,
                    path.display().to_string(),
                    fetched.bytes.len() as u64,
                ));
            }
            // A refused sign-in stops the batch: every other file would fail too.
            Err(f) if f.error.is_auth() && f.error.reason() != Some(Reason::Forbidden) => {
                return Err(f.error)
            }
            Err(f) => skipped.push(
                SkippedDocument::new(item.document.id.clone(), f.error.message().to_string())
                    .with_code(f.code),
            ),
        }
    }
    let batch = DownloadBatch::new(dir.display().to_string(), saved).with_skipped(skipped);
    if ctx.json {
        output::json(&serde_json::to_value(&batch).unwrap_or(Value::Null));
    } else {
        println!(
            "Saved {} documents ({} bytes) to {}{}.",
            batch.count,
            batch.bytes_total,
            batch.dir,
            if batch.skipped.is_empty() {
                String::new()
            } else {
                format!("; skipped {}", batch.skipped.len())
            }
        );
        for s in &batch.skipped {
            eprintln!(
                "skipped {} ({}): {}",
                s.id,
                s.code.as_deref().unwrap_or(""),
                s.reason
            );
        }
    }
    Ok(())
}

fn api(ctx: &Ctx, args: ApiCmd) -> Result<(), CliError> {
    if !args.method.eq_ignore_ascii_case("GET") {
        return Err(CliError::Usage(format!(
            "athena is read-only: `api` takes GET, not {}",
            args.method
        )));
    }
    if args.path.trim().is_empty() {
        return Err(CliError::Usage("api needs a path".into()));
    }
    let (entry, tokens) = open_session(ctx, &args.select)?;
    let http = BlockingTransport::new()?;
    let lock = RefreshLock::for_binary(BIN)?;
    let store = KeychainStore::new();
    let mut client = Client::new(&http, &store, Some(&lock), entry.key(), tokens.clone());
    let result = client
        .resolve(&args.path)
        .and_then(|url| client.get(&url, fhir::FHIR_JSON));
    note_renewal(ctx, &entry, &tokens, client.tokens());
    let response = result?;
    fhir::check(&response, &args.path)?;
    match serde_json::from_str::<Value>(&response.body) {
        Ok(value) => output::json(&value),
        Err(_) => println!("{}", response.body),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_synthetic_servers_may_be_written_to_a_plain_file() {
        for base in [
            "http://127.0.0.1:4100/fhir/r4",
            "http://localhost:4100/x/fhir/r4",
            "https://api.preview.platform.athenahealth.com/fhir/r4",
            "https://api.preview.platform.athenahealth.com/fhir/r4/",
            "https://api.preview.platform.athenahealth.com/80000/brand/1/csg/1/fhir/r4",
            "https://api.preview.platform.athenahealth.com/195900/brand/1/csg/1/fhir/r4",
        ] {
            assert!(synthetic(base), "{base}");
        }
        for base in [
            "https://api.platform.athenahealth.com/fhir/r4",
            "https://api.platform.athenahealth.com/80000/brand/1/csg/1/fhir/r4",
            "https://api.preview.platform.athenahealth.com/900001/brand/1/csg/1/fhir/r4",
            "https://api.preview.platform.athenahealth.com/800001/fhir/r4",
            "https://api.preview.platform.athenahealth.com.example/fhir/r4",
            "https://127.0.0.1.example/fhir/r4",
            "http://127.0.0.1.example:80/fhir/r4",
            "not a url",
        ] {
            assert!(!synthetic(base), "{base}");
        }
    }

    #[test]
    fn the_command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn labels_are_checked() {
        assert!(validate_label("kid1").is_ok());
        assert!(validate_label("kid_2").is_ok());
        assert!(validate_label("two words").is_err());
        assert!(validate_label("").is_err());
    }
}
