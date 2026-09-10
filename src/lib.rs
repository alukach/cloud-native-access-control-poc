pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn cql2_evaluates_a_spatial_predicate() {
        let e: cql2::Expr = "S_INTERSECTS(geom, POINT(5 5))".parse().unwrap();
        let ctx = serde_json::json!({
            "geom": {"type":"Polygon","coordinates":[[[0,0],[10,0],[10,10],[0,10],[0,0]]]}
        });
        assert!(e.matches(Some(&ctx)).unwrap());
    }
}
