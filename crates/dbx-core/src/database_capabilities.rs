use crate::models::connection::DatabaseType;

pub fn agent_key(db_type: &DatabaseType, driver_profile: Option<&str>) -> Option<&'static str> {
    match db_type {
        DatabaseType::Dameng => Some("dameng"),
        DatabaseType::Kingbase => Some("kingbase"),
        DatabaseType::Highgo => Some("highgo"),
        DatabaseType::Vastbase => Some("vastbase"),
        DatabaseType::Goldendb => Some("goldendb"),
        DatabaseType::Yashandb => Some("yashandb"),
        DatabaseType::Databricks => Some("databricks"),
        DatabaseType::SapHana => Some("saphana"),
        DatabaseType::Teradata => Some("teradata"),
        DatabaseType::Vertica => Some("vertica"),
        DatabaseType::Firebird => Some("firebird"),
        DatabaseType::Exasol => Some("exasol"),
        DatabaseType::OceanbaseOracle => Some("oceanbase-oracle"),
        DatabaseType::Gbase => Some("gbase"),
        DatabaseType::Oracle => match driver_profile {
            Some("oracle-10g") => Some("oracle-10g"),
            _ => Some("oracle"),
        },
        DatabaseType::H2 => Some("h2"),
        DatabaseType::Snowflake => Some("snowflake"),
        DatabaseType::Trino => Some("trino"),
        DatabaseType::Hive => Some("hive"),
        DatabaseType::Db2 => Some("db2"),
        DatabaseType::Informix => Some("informix"),
        DatabaseType::Neo4j => Some("neo4j"),
        DatabaseType::Cassandra => Some("cassandra"),
        DatabaseType::Bigquery => Some("bigquery"),
        DatabaseType::Kylin => Some("kylin"),
        DatabaseType::Sundb => Some("sundb"),
        DatabaseType::MongoDb => Some("mongodb"),
        DatabaseType::Tdengine => Some("tdengine"),
        DatabaseType::Access => Some("access"),
        _ => None,
    }
}

pub fn is_agent_type(db_type: &DatabaseType) -> bool {
    agent_key(db_type, None).is_some()
}

pub fn is_single_connection_pool(db_type: &DatabaseType) -> bool {
    matches!(
        db_type,
        DatabaseType::Sqlite
            | DatabaseType::DuckDb
            | DatabaseType::MongoDb
            | DatabaseType::Oracle
            | DatabaseType::Dameng
            | DatabaseType::Kingbase
            | DatabaseType::Highgo
            | DatabaseType::Vastbase
            | DatabaseType::Goldendb
            | DatabaseType::Yashandb
            | DatabaseType::Firebird
            | DatabaseType::OceanbaseOracle
            | DatabaseType::Access
            | DatabaseType::Jdbc
    )
}

pub fn is_metadata_connection_scoped(db_type: &DatabaseType) -> bool {
    matches!(db_type, DatabaseType::Mysql | DatabaseType::Doris | DatabaseType::StarRocks)
}

pub fn skips_tcp_probe(db_type: &DatabaseType) -> bool {
    matches!(db_type, DatabaseType::Sqlite | DatabaseType::DuckDb | DatabaseType::Jdbc) || is_agent_type(db_type)
}
