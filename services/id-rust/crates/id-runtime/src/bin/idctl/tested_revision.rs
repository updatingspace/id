//! Fail-closed deployment gate for the exact source SHA and all required CI jobs.

use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Url, header};
use serde_json::Value;
use std::{collections::BTreeMap, env, time::Duration};

const WORKFLOW: &str = ".github/workflows/ci-cd.yml";
const REQUIRED_JOBS: [&str; 4] = [
    "Rust API and Topcoat",
    "Rust YDB schema and auth integration",
    "Terraform validate",
    "OpenTofu validate",
];

fn validate_run(run: &Value, sha: &str, repository: &str) -> Result<u64> {
    let path = run["path"].as_str().unwrap_or_default();
    ensure!(
        run["head_sha"] == sha
            && run["head_repository"]["full_name"] == repository
            && path.split('@').next() == Some(WORKFLOW)
            && run["event"] == "push"
            && matches!(run["head_branch"].as_str(), Some("main" | "master"))
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "deployment requires successful push CI for this repository and SHA on main/master"
    );
    run["id"].as_u64().context("CI run omitted numeric ID")
}

fn validate_jobs(jobs: &[Value]) -> Result<()> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for job in jobs {
        let Some(name) = job["name"].as_str() else {
            continue;
        };
        if REQUIRED_JOBS.contains(&name) {
            ensure!(
                job["status"] == "completed" && job["conclusion"] == "success",
                "required CI job missing or unsuccessful: {name}"
            );
            *counts.entry(name).or_default() += 1;
        }
    }
    for name in REQUIRED_JOBS {
        ensure!(
            counts.get(name) == Some(&1),
            "required CI job missing or duplicated: {name}"
        );
    }
    Ok(())
}

fn newest_run<'a>(runs: &'a [Value], sha: &str) -> Result<&'a Value> {
    runs.iter()
        .filter(|run| run["head_sha"] == sha)
        .max_by_key(|run| {
            (
                run["run_number"].as_u64().unwrap_or_default(),
                run["run_attempt"].as_u64().unwrap_or(1),
            )
        })
        .context("no push CI run exists for the deployment SHA")
}

struct Github {
    client: Client,
    base: String,
    token: String,
}

impl Github {
    fn new(api: &str, token: String) -> Result<Self> {
        let parsed = Url::parse(api).context("invalid GITHUB_API_URL")?;
        ensure!(
            parsed.scheme() == "https"
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "GITHUB_API_URL must be a plain HTTPS URL"
        );
        ensure!(!token.is_empty(), "GH_TOKEN is empty");
        Ok(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            base: api.trim_end_matches('/').to_owned(),
            token,
        })
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}{path}", self.base))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("GitHub CI API unavailable")?;
        ensure!(
            response.status().is_success(),
            "GitHub CI API returned {}",
            response.status()
        );
        let body = response.bytes().await?;
        ensure!(
            body.len() <= 10 * 1024 * 1024,
            "GitHub CI response too large"
        );
        serde_json::from_slice(&body).context("GitHub CI API returned invalid JSON")
    }
}

fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    };
    parts.next().is_some_and(valid_part)
        && parts.next().is_some_and(valid_part)
        && parts.next().is_none()
}

async fn check(api: &Github, repository: &str, sha: &str, run_id: Option<u64>) -> Result<u64> {
    ensure!(valid_repository(repository), "invalid GITHUB_REPOSITORY");
    ensure!(
        sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "DEPLOY_SHA must be a full Git SHA"
    );
    let base = format!("/repos/{repository}/actions");
    let run = if let Some(id) = run_id {
        api.get(&format!("{base}/runs/{id}")).await?
    } else {
        let listed = api
            .get(&format!(
                "{base}/workflows/ci-cd.yml/runs?head_sha={sha}&event=push&per_page=100"
            ))
            .await?;
        let runs = listed["workflow_runs"]
            .as_array()
            .context("GitHub CI listing omitted workflow_runs")?;
        newest_run(runs, sha)?.clone()
    };
    let id = validate_run(&run, sha, repository)?;
    let mut jobs = Vec::new();
    for page in 1..=100 {
        let result = api
            .get(&format!(
                "{base}/runs/{id}/jobs?filter=latest&per_page=100&page={page}"
            ))
            .await?;
        let total = result["total_count"]
            .as_u64()
            .context("GitHub CI jobs omitted total_count")?;
        let batch = result["jobs"]
            .as_array()
            .context("GitHub CI jobs omitted jobs array")?;
        ensure!(
            !batch.is_empty() || jobs.len() as u64 >= total,
            "incomplete CI job response"
        );
        jobs.extend(batch.iter().cloned());
        if jobs.len() as u64 >= total {
            validate_jobs(&jobs)?;
            return Ok(id);
        }
    }
    bail!("GitHub CI jobs exceeded pagination limit")
}

pub(super) async fn run() -> Result<()> {
    let token = env::var("GH_TOKEN").context("GH_TOKEN required")?;
    let repository = env::var("GITHUB_REPOSITORY").context("GITHUB_REPOSITORY required")?;
    let sha = env::var("DEPLOY_SHA").context("DEPLOY_SHA required")?;
    let run_id = env::var("CI_RUN_ID")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>().context("invalid CI_RUN_ID"))
        .transpose()?;
    let api = Github::new(
        &env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".into()),
        token,
    )?;
    let id = check(&api, &repository, &sha, run_id).await?;
    println!("Verified required CI jobs in run {id} for deployment revision.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, http::Uri, routing::get};

    #[test]
    fn required_jobs_match_current_ci_workflow() {
        let workflow = include_str!("../../../../../../../.github/workflows/ci-cd.yml");
        let jobs = workflow
            .lines()
            .filter_map(|line| line.strip_prefix("    name: "))
            .collect::<Vec<_>>();
        assert_eq!(jobs, REQUIRED_JOBS);
    }

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn run() -> Value {
        serde_json::json!({
            "id":10,"run_number":3,"run_attempt":1,
            "head_sha":SHA,"head_repository":{"full_name":"org/id"},
            "head_branch":"main","path":WORKFLOW,"event":"push",
            "status":"completed","conclusion":"success"
        })
    }

    fn jobs() -> Vec<Value> {
        REQUIRED_JOBS
            .iter()
            .map(
                |name| serde_json::json!({"name":name,"status":"completed","conclusion":"success"}),
            )
            .collect()
    }

    #[test]
    fn exact_run_and_jobs_are_required() -> Result<()> {
        assert_eq!(validate_run(&run(), SHA, "org/id")?, 10);
        validate_jobs(&jobs())?;
        for (field, value) in [
            ("head_sha", Value::String("other".into())),
            ("event", Value::String("pull_request".into())),
            ("head_branch", Value::String("feature".into())),
            ("status", Value::String("in_progress".into())),
            ("conclusion", Value::String("failure".into())),
            ("path", Value::String(".github/workflows/other.yml".into())),
        ] {
            let mut bad = run();
            bad[field] = value;
            assert!(validate_run(&bad, SHA, "org/id").is_err());
        }
        let mut wrong_repo = run();
        wrong_repo["head_repository"]["full_name"] = Value::String("fork/id".into());
        assert!(validate_run(&wrong_repo, SHA, "org/id").is_err());
        for conclusion in ["skipped", "failure", "cancelled", "neutral"] {
            let mut bad = jobs();
            bad[0]["conclusion"] = Value::String(conclusion.into());
            assert!(validate_jobs(&bad).is_err());
        }
        let mut missing = jobs();
        missing.pop();
        assert!(validate_jobs(&missing).is_err());
        let mut duplicated = jobs();
        duplicated.push(duplicated[0].clone());
        assert!(validate_jobs(&duplicated).is_err());
        Ok(())
    }

    #[test]
    fn newest_failure_cannot_hide_behind_older_success() -> Result<()> {
        let old = run();
        let mut newer = run();
        newer["id"] = Value::from(11);
        newer["run_number"] = Value::from(4);
        newer["conclusion"] = Value::String("failure".into());
        let runs = vec![old, newer];
        assert!(validate_run(newest_run(&runs, SHA)?, SHA, "org/id").is_err());
        assert!(newest_run(&[], SHA).is_err());
        assert!(valid_repository("org/id"));
        assert!(!valid_repository("org/id/extra"));
        Ok(())
    }

    #[tokio::test]
    async fn fetches_every_jobs_page_before_passing() -> Result<()> {
        let app = Router::new().fallback(get(|uri: Uri| async move {
            let path = uri.path();
            if path.ends_with("/runs/10") {
                return Json(run());
            }
            let all = jobs();
            let page = uri.query().and_then(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == "page")
                    .map(|(_, value)| value.into_owned())
            });
            if page.as_deref() == Some("1") {
                return Json(serde_json::json!({"jobs":all[..3],"total_count":all.len()}));
            }
            if page.as_deref() == Some("2") {
                return Json(serde_json::json!({"jobs":all[3..],"total_count":all.len()}));
            }
            Json(serde_json::json!({"jobs":[],"total_count":all.len()}))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let api = Github {
            client: Client::new(),
            base: format!("http://{address}"),
            token: "synthetic-test-token".into(),
        };
        let checked = check(&api, "org/id", SHA, Some(10)).await;
        server.abort();
        assert_eq!(checked?, 10);
        Ok(())
    }
}
