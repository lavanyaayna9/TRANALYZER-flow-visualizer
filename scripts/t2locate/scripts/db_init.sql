-- Using tabs causes issues with empty fields
.separator "\a"

-- Delete old data
DROP TABLE IF EXISTS locations;
DROP TABLE IF EXISTS locations_info;
DROP TABLE IF EXISTS locations_index;

-- Apply schema
.read scripts/db.schema

-- Import data
.import data/locations.asv locations

-- Generate rtree index table
INSERT INTO
    locations_index
SELECT
    id, latitude, latitude, longitude, longitude
FROM
    locations;

-- Resolve names of administrative regions
INSERT INTO
    locations_info
SELECT
    loc.id, loc.countrycode, MIN(adm1.name), MIN(adm2.name), MIN(adm3.name), MIN(adm4.name), loc.name
FROM
    locations loc
    LEFT JOIN locations AS adm1 ON loc.countrycode = adm1.countrycode AND adm1.admin1code = loc.admin1code AND adm1.featurecode = 'ADM1'
    LEFT JOIN locations AS adm2 ON loc.countrycode = adm2.countrycode AND adm2.admin2code = loc.admin2code AND adm2.featurecode = 'ADM2'
    LEFT JOIN locations AS adm3 ON loc.countrycode = adm3.countrycode AND adm3.admin3code = loc.admin3code AND adm3.featurecode = 'ADM3'
    LEFT JOIN locations AS adm4 ON loc.countrycode = adm4.countrycode AND adm4.admin4code = loc.admin4code AND adm4.featurecode = 'ADM4'
GROUP BY
    loc.id, loc.countrycode, loc.name;

-- Insert dummy data to allow for simpler queries
INSERT INTO locations_info VALUES (0, '-', '-', '-', '-', '-', '-');
INSERT INTO locations_index VALUES (0, -180.0, 180.0, -180.0, 180.0);
