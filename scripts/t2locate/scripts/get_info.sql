-- Get all the information of a location based on the location ID
SELECT
    %s, %s, country, admin1, admin2, admin3, admin4, name, '%s'
FROM
    locations_info
WHERE
    id=%s;
\n