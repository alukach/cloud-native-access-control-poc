//! Policy loading with static property validation.
//!
//! # Why validation happens at load time and not at evaluation time
//!
//! A misspelled property in a policy is the failure mode this module exists to
//! prevent, and cql2 cannot report one at evaluation time. An unresolved
//! property is not an error in CQL2; it is the third truth value, and the
//! reduction rules over that value discard it in two ways that both fail open:
//!
//! * `isNull` folds an unresolved property to TRUE whenever a record is in
//!   hand, on the reading that an absent field is a null one. So
//!   `region.knid IS NULL` -- pure typo -- evaluates to `Ok(true)`, and any
//!   rule guarded that way grants.
//! * The connectives absorb: `FALSE AND _` is FALSE and `TRUE OR _` is TRUE
//!   whatever the other operand is, unfolded operands included. So in
//!   `region.knid = 'x' OR region.kind = 'metadata'` the typo never reaches the
//!   answer -- the rule behaves exactly as if the misspelled clause were not
//!   there, silently widening or narrowing without a diagnostic.
//!
//! These were measured against cql2 0.6, not inferred. The consequence for
//! testing is sharp: **a test asserting "a filter naming a nonexistent property
//! denies" passes while proving nothing**, because the two mechanisms above
//! decide those cases for unrelated reasons. The only defence that actually
//! holds is walking the parsed AST before the policy is ever evaluated and
//! refusing to load one that names a property outside the queryables schema.
//! That is [`validate`], and the tests that defend it name the *variant* they
//! reach rather than the outcome they observe.

use cql2::Expr;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is not valid YAML: {0}")]
    Yaml(#[from] serde_norway::Error),
    #[error("filter does not parse as CQL2: {0}")]
    Parse(String),
    #[error("unknown property `{0}` - not in the queryables schema")]
    UnknownProperty(String),
    #[error("operator `{0}` is banned in policies")]
    BannedOperator(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    allow: Vec<String>,
}

/// A loaded, validated allow-list. Every property named by every rule is known
/// to be in the queryables schema; no rule can be constructed otherwise.
#[derive(Debug)]
pub struct Policy {
    rules: Vec<Expr>,
}

impl Policy {
    /// Parse and validate a policy document.
    ///
    /// `queryables` is the closed set of property names a rule may name. A rule
    /// naming anything else is a load failure, not a runtime denial -- see the
    /// module docs for why the distinction is the whole point.
    pub fn load(yaml: &str, queryables: &[&str]) -> Result<Self, PolicyError> {
        let file: PolicyFile = serde_norway::from_str(yaml)?;
        let mut rules = Vec::with_capacity(file.allow.len());
        for src in file.allow {
            // `Expr: FromStr` reads a leading `{` as cql2-json and anything
            // else as cql2-text. Both paths normalize, so `validate` sees
            // canonical operator spellings whichever encoding was written.
            let expr: Expr = src
                .parse()
                .map_err(|e| PolicyError::Parse(format!("{e}")))?;
            validate(&expr, queryables)?;
            rules.push(expr);
        }
        Ok(Self { rules })
    }

    /// True if ANY rule matches. An evaluation error denies.
    ///
    /// Disjunctive over rules, so an empty allow-list denies everything -- the
    /// right default for a document whose only content is grants.
    ///
    /// `unwrap_or(false)` is the fail-closed half of the contract and it covers
    /// every error `matches` can raise: an unresolved property leaves the
    /// operation unfolded and surfaces as `NonReduced`, and so does a
    /// comparison whose operands are of different kinds -- a string bound on a
    /// numeric property, say. Both must deny. A rule that evaluates to CQL2
    /// NULL is not an error at all (`matches` returns `Ok(false)`), which is
    /// also a denial, so all three roads lead to the same place.
    ///
    /// # Cost
    ///
    /// Each rule is cloned on each call, because `Expr::matches` consumes the
    /// expression. Measured at ~20.6us for a spatial rule, dominated not by the
    /// clone but by cql2 re-parsing the policy's GeoJSON through WKT on every
    /// evaluation -- a cost inside `matches` that no amount of caching on this
    /// side removes. Deliberately left alone: correctness of the clone (each
    /// call starts from the pristine parsed rule, so no reduction can leak into
    /// the next call) matters more here than the microseconds, and a `check()`
    /// evaluates one context per overlapped region, not per byte.
    pub fn permits(&self, ctx: &Value) -> bool {
        // cql2 resolves a property by dot-path against the context and, failing
        // that, retries under `properties.{name}`. That fallback is rooted at
        // the context object, so a top-level `properties` key -- and only a
        // top-level one -- can shadow a policy property name with data. A
        // caller that folded file-derived JSON into the context under that key
        // would hand the file authority over the decision. Refuse the context
        // rather than trust the caller to have built it right.
        //
        // The guard is shallow because the shadowing is: `a_nested_properties_
        // key_cannot_shadow` pins that a `properties` key deeper in the tree is
        // unreachable by the fallback.
        let Some(obj) = ctx.as_object() else {
            // Not dot-addressable, so no rule that names a property could be
            // decided against it. Denying outright also refuses a context whose
            // shape the guard above cannot inspect.
            return false;
        };
        if obj.contains_key("properties") {
            return false;
        }
        self.rules
            .iter()
            .any(|r| r.clone().matches(Some(ctx)).unwrap_or(false))
    }
}

/// Operators a policy may not use, in cql2's canonical spelling.
///
/// `isNull` is here because it is the one reduction in cql2 0.6 that turns an
/// unresolved property into TRUE (see the module docs). Every other operator
/// either leaves an unknown operand unfolded -- `between`, `not`, the
/// comparisons, the spatial and temporal predicates, `in` -- which reaches
/// `permits` as an error and denies, or propagates NULL, which denies too. So
/// the ban is exactly one operator wide, and that narrowness is a finding
/// rather than an oversight: it was read off cql2's `reduce`, arm by arm.
///
/// Banning it costs policy authors an "is this field absent?" test. That test
/// is not one an authorization rule should want: absent and null are
/// indistinguishable to cql2, `Region::props` never emits null, and a rule that
/// grants on absence grants on every future region kind that happens to omit
/// the field.
const BANNED_OPS: &[&str] = &["isNull"];

/// Reject any expression naming a property outside `queryables`, or using a
/// banned operator.
///
/// # The match is exhaustive on purpose
///
/// There is no `_` arm. Three of `cql2::Expr`'s twelve variants hold nested
/// expressions without being obviously container-shaped -- `Date`, `Timestamp`
/// and `BBox` each reachable from cql2-text as an ordinary function call
/// (`date(x)`, `timestamp(x)`, `bbox(a,b,c,d)`) -- and a wildcard arm would
/// have swallowed a typo inside any of them while every other test still
/// passed. A wildcard also makes a cql2 upgrade that adds a variant silently
/// widen every policy in existence. Listing all twelve turns that upgrade into
/// a compile error, which is the only place it can be caught.
fn validate(expr: &Expr, queryables: &[&str]) -> Result<(), PolicyError> {
    match expr {
        Expr::Property { property } => {
            if queryables.contains(&property.as_str()) {
                Ok(())
            } else {
                Err(PolicyError::UnknownProperty(property.clone()))
            }
        }
        Expr::Operation { op, args } => {
            // Operands before the operator, so `region.knid IS NULL` -- a
            // filter that is *both* a typo and a banned operator -- is reported
            // as the typo. The typo is the root cause and the actionable half:
            // told only that `IS NULL` is banned, an author rewrites the guard
            // and carries the misspelling into whatever replaces it.
            args.iter().try_for_each(|a| validate(a, queryables))?;
            // Compared case-insensitively even though parsing has already run
            // `canonical_op` over the name. cql2 resolves operator names
            // case-insensitively and through aliases, so `ISNULL(x)`, `x IS
            // NULL` and the cql2-json `{"op":"isNull"}` all arrive here as
            // `isNull` -- but this function is also reachable for an `Expr`
            // built by hand, which never passed through normalization. A ban
            // that matched one spelling of the name would be decorative.
            if let Some(banned) = BANNED_OPS
                .iter()
                .find(|b| b.eq_ignore_ascii_case(op.as_str()))
            {
                return Err(PolicyError::BannedOperator((*banned).to_string()));
            }
            Ok(())
        }
        Expr::Interval { interval } => interval.iter().try_for_each(|a| validate(a, queryables)),
        Expr::Timestamp { timestamp } => validate(timestamp, queryables),
        Expr::Date { date } => validate(date, queryables),
        Expr::BBox { bbox } => bbox.iter().try_for_each(|a| validate(a, queryables)),
        Expr::Array(items) => items.iter().try_for_each(|a| validate(a, queryables)),
        // Leaves. `Geometry` holds a `cql2::Geometry`, which is GeoJSON or WKT
        // and cannot contain an `Expr`, so a policy's literal geometry is data
        // all the way down.
        Expr::Float(_) | Expr::Literal(_) | Expr::Bool(_) | Expr::Geometry(_) | Expr::Null => {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const QUERYABLES: &[&str] = &[
        "user.role",
        "region.kind",
        "region.column",
        "region.row_group",
        "region.overview_level",
        "region.x",
        "region.y",
        "region.geom",
        "region.bbox",
        "region.crs",
        "region.name",
    ];

    fn load(yaml: &str) -> Result<Policy, PolicyError> {
        Policy::load(yaml, QUERYABLES)
    }

    #[test]
    fn a_typo_is_rejected_at_load_not_at_evaluation() {
        // Each of these evaluates to Ok(true) or hides the typo at runtime.
        for f in [
            "region.knid = 'metadata'",
            "region.knid IS NULL",
            "region.knid = 'x' OR region.kind = 'metadata'",
        ] {
            let err = load(&format!("allow:\n  - \"{f}\"")).unwrap_err();
            assert!(matches!(err, PolicyError::UnknownProperty(_)), "{f}");
        }
    }

    #[test]
    fn is_null_is_banned_outright() {
        // cql2 folds an absent property to true for isNull: a guard written
        // this way grants on a typo the validator might not otherwise see.
        let err = load("allow:\n  - \"region.column IS NULL\"").unwrap_err();
        assert!(matches!(err, PolicyError::BannedOperator(_)));
    }

    #[test]
    fn valid_policy_loads() {
        assert!(load("allow:\n  - \"region.kind = 'metadata'\"").is_ok());
    }

    #[test]
    fn rules_are_disjunctive() {
        let p =
            load("allow:\n  - \"region.kind = 'metadata'\"\n  - \"region.kind = 'tile'\"").unwrap();
        assert!(p.permits(&json!({"region":{"kind":"tile"}})));
        assert!(!p.permits(&json!({"region":{"kind":"unmapped"}})));
    }

    #[test]
    fn evaluation_error_denies() {
        // An unguarded column rule errors against a tile region. It must deny,
        // never leak through as true.
        let p = load("allow:\n  - \"region.column <> 'salary'\"").unwrap();
        assert!(!p.permits(&json!({"region":{"kind":"tile","x":1}})));
    }

    #[test]
    fn empty_allow_list_denies_everything() {
        let p = load("allow: []").unwrap();
        assert!(!p.permits(&json!({"region":{"kind":"metadata"}})));
    }

    #[test]
    fn context_may_not_contain_a_properties_key() {
        // cql2 falls back to `properties.{name}`, so data could shadow a
        // policy property name.
        let p = load("allow:\n  - \"region.kind = 'metadata'\"").unwrap();
        assert!(!p.permits(&json!({"properties":{"region":{"kind":"metadata"}}})));
    }

    // ---- Beyond the spec ---------------------------------------------------

    /// The whole guarantee of this module rests on `validate` reaching every
    /// `Expr` that can hold a nested `Expr`. One filter per container variant
    /// of `cql2::Expr`, each hiding the same typo. A variant the walk forgets
    /// shows up here as an `Ok`.
    #[test]
    fn a_typo_is_rejected_inside_every_container_variant() {
        for (variant, filter) in [
            // Expr::Operation { args }
            ("Operation", "region.knid = 'x'"),
            // Expr::Operation, one level down a user-defined function, whose
            // name cql2 leaves alone rather than resolving.
            ("Operation/function", "lower(region.knid) = 'x'"),
            // Expr::Array -- the right-hand side of IN.
            ("Array", "region.kind IN ('a', region.knid)"),
            // Expr::Interval { interval }, via the `interval` function.
            (
                "Interval",
                "T_INTERSECTS(interval(region.knid, region.name), \
                 interval('2020-01-01','2020-01-02'))",
            ),
            // Expr::Timestamp { timestamp }, via the `timestamp` function.
            (
                "Timestamp",
                "timestamp(region.knid) = timestamp(region.name)",
            ),
            // Expr::Date { date }, via the `date` function.
            ("Date", "date(region.knid) = date(region.name)"),
            // Expr::BBox { bbox }, via the `bbox` function.
            (
                "BBox",
                "S_INTERSECTS(region.geom, bbox(region.knid, 0, 1, 1))",
            ),
        ] {
            let err =
                load(&format!("allow:\n  - \"{filter}\"")).unwrap_err_or_panic(variant, filter);
            assert!(
                matches!(err, PolicyError::UnknownProperty(ref p) if p == "region.knid"),
                "{variant}: {filter} produced {err:?}"
            );
        }
    }

    /// Absorption hides a typo whichever way the sibling decides the result.
    #[test]
    fn a_typo_absorbed_by_a_boolean_sibling_is_still_rejected() {
        for f in [
            "region.knid = 'x' AND region.kind = 'tile'",
            "region.knid = 'x' OR region.kind = 'metadata'",
            "NOT (region.knid = 'x')",
            "region.knid BETWEEN 1 AND 2",
        ] {
            let err = load(&format!("allow:\n  - \"{f}\"")).unwrap_err();
            assert!(matches!(err, PolicyError::UnknownProperty(_)), "{f}");
        }
    }

    /// cql2 resolves operator names case-insensitively and through aliases, so
    /// a ban that matched one spelling would be decorative.
    #[test]
    fn the_is_null_ban_survives_every_spelling() {
        for f in [
            "region.column IS NULL",
            "region.column IS NOT NULL",
            "isNull(region.column)",
            "ISNULL(region.column)",
            "isnull(region.column)",
            // cql2-json: `parse` reads a leading `{` as the JSON encoding.
            r#"{\"op\":\"isNull\",\"args\":[{\"property\":\"region.column\"}]}"#,
        ] {
            let err = load(&format!("allow:\n  - \"{f}\"")).unwrap_err();
            assert!(
                matches!(err, PolicyError::BannedOperator(_)),
                "{f}: {err:?}"
            );
        }
    }

    /// The `properties.{name}` fallback is rooted at the context object, so a
    /// `properties` key nested deeper cannot shadow. Pinned so the shallow
    /// guard in `permits` is known to be sufficient rather than assumed to be.
    #[test]
    fn a_nested_properties_key_cannot_shadow() {
        let p = load("allow:\n  - \"region.kind = 'metadata'\"").unwrap();
        assert!(!p.permits(&json!({"region":{"properties":{"kind":"metadata"}}})));
        assert!(p.permits(&json!({"region":{"kind":"metadata"},"other":{"properties":{}}})));
    }

    /// A comparison whose operands are of different kinds does not fold, which
    /// reaches `permits` as an error rather than as a truth value.
    #[test]
    fn a_type_mismatch_denies() {
        let p = load("allow:\n  - \"region.overview_level >= '2'\"").unwrap();
        assert!(!p.permits(&json!({"region":{"kind":"tile","overview_level":4}})));
        // The same rule against the same value, correctly typed, does permit --
        // otherwise the assertion above would pass for the wrong reason.
        let p = load("allow:\n  - \"region.overview_level >= 2\"").unwrap();
        assert!(p.permits(&json!({"region":{"kind":"tile","overview_level":4}})));
    }

    /// A present JSON `null` reduces to CQL2 NULL, which is not a match.
    #[test]
    fn a_null_valued_property_denies() {
        let p = load("allow:\n  - \"region.column = 'salary'\"").unwrap();
        assert!(!p.permits(&json!({"region":{"kind":"column_chunk","column":null}})));
    }

    #[test]
    fn a_filter_that_is_not_cql2_is_rejected() {
        assert!(matches!(
            load("allow:\n  - \"region.kind = = 'x'\"").unwrap_err(),
            PolicyError::Parse(_)
        ));
    }

    #[test]
    fn a_policy_without_an_allow_key_is_rejected() {
        assert!(matches!(
            load("deny: []").unwrap_err(),
            PolicyError::Yaml(_)
        ));
    }

    /// A key this crate does not read is a key whose rules never run. Silently
    /// ignoring `deny:` would load a policy the author believes restricts
    /// access and that in fact does not, which is the worst way to be wrong.
    #[test]
    fn an_unrecognised_top_level_key_is_rejected() {
        let err = load("allow:\n  - \"region.kind = 'tile'\"\ndeny:\n  - \"true\"").unwrap_err();
        assert!(matches!(err, PolicyError::Yaml(_)), "{err:?}");
    }

    /// Every rule is validated, not just the first.
    #[test]
    fn a_typo_in_a_later_rule_is_rejected() {
        let err =
            load("allow:\n  - \"region.kind = 'tile'\"\n  - \"region.knid = 'x'\"").unwrap_err();
        assert!(matches!(err, PolicyError::UnknownProperty(_)));
    }

    /// A rule may reference a property no region of the matched kind carries;
    /// only names outside the schema are rejected. `evaluation_error_denies`
    /// pins what happens at runtime.
    #[test]
    fn a_known_property_absent_from_this_region_kind_still_loads() {
        assert!(
            load("allow:\n  - \"region.kind = 'column_chunk' AND region.column <> 'salary'\"")
                .is_ok()
        );
    }

    /// A filter that is both a typo and a banned operator reports the typo.
    /// Pinned because the two spec tests above depend on the order the walk
    /// visits an operation's operands and its name in, and nothing else would
    /// say that the order is deliberate.
    #[test]
    fn a_typo_inside_a_banned_operator_reports_the_typo() {
        let err = load("allow:\n  - \"region.knid IS NULL\"").unwrap_err();
        assert!(matches!(err, PolicyError::UnknownProperty(ref p) if p == "region.knid"));
    }

    /// A context that is not a JSON object cannot be dot-addressed, so nothing
    /// about it is authorizable.
    #[test]
    fn a_non_object_context_denies() {
        let p = load("allow:\n  - \"true\"").unwrap();
        assert!(p.permits(&json!({})));
        assert!(!p.permits(&json!([{"region":{"kind":"metadata"}}])));
        assert!(!p.permits(&json!("region")));
    }

    /// `permits` clones each rule, since `matches` consumes the expression.
    /// Two calls must therefore agree.
    #[test]
    fn evaluating_twice_gives_the_same_answer() {
        let p =
            load("allow:\n  - \"S_INTERSECTS(region.geom, POLYGON((0 0,10 0,10 10,0 10,0 0)))\"")
                .unwrap();
        let ctx = json!({"region":{"kind":"tile","geom":{"type":"Point","coordinates":[5,5]}}});
        assert!(p.permits(&ctx));
        assert!(p.permits(&ctx));
        let outside =
            json!({"region":{"kind":"tile","geom":{"type":"Point","coordinates":[50,50]}}});
        assert!(!p.permits(&outside));
        assert!(!p.permits(&outside));
    }

    /// Test-only helper: `unwrap_err` with the case named in the panic.
    trait UnwrapErrOrPanic<E> {
        fn unwrap_err_or_panic(self, variant: &str, filter: &str) -> E;
    }
    impl<T, E> UnwrapErrOrPanic<E> for Result<T, E> {
        fn unwrap_err_or_panic(self, variant: &str, filter: &str) -> E {
            match self {
                Err(e) => e,
                Ok(_) => panic!("{variant}: `{filter}` loaded, so the walk misses that variant"),
            }
        }
    }
}
