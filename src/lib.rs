pub mod decision;
pub mod index;
pub mod policy;
pub mod range;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn cql2_evaluates_a_spatial_predicate() {
        let ctx = serde_json::json!({
            "geom": {"type":"Polygon","coordinates":[[[0,0],[10,0],[10,10],[0,10],[0,0]]]}
        });

        let inside: cql2::Expr = "S_INTERSECTS(geom, POINT(5 5))".parse().unwrap();
        assert!(inside.matches(Some(&ctx)).unwrap());

        // The direction that matters for an authorization crate: a regression
        // that made `matches` fail open would pass the assertion above alone.
        let outside: cql2::Expr = "S_INTERSECTS(geom, POINT(50 50))".parse().unwrap();
        assert!(!outside.matches(Some(&ctx)).unwrap());
    }
}
