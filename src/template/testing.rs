//! Runs the `tests` block of templates.

use anyhow::Result;

use crate::detect::Engine;
use crate::render;
use crate::template::Template;

/// Returns a list of human readable failures (empty when all pass).
pub fn run(t: &Template) -> Result<Vec<String>> {
    let engine = Engine::new(vec![t.clone()])?;
    let builtins = render::builtin_vars();
    let mut failures = Vec::new();
    let Some(tests) = &t.tests else {
        return Ok(failures);
    };
    for (i, s) in tests.positive.iter().enumerate() {
        let sample = render::render(s, &builtins)?;
        if engine.scan(&sample).is_empty() {
            failures.push(format!("positive sample #{} did not match", i + 1));
        }
    }
    for (i, s) in tests.negative.iter().enumerate() {
        let sample = render::render(s, &builtins)?;
        if !engine.scan(&sample).is_empty() {
            failures.push(format!("negative sample #{} matched", i + 1));
        }
    }
    Ok(failures)
}
