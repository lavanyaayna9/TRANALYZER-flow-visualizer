/*
We recursively increase the scale, searching for a bigger and bigger area.
The dummy data with ID 0 we inserted into the database during the init
step covers the whole world and will always be found in case there is no
better match. This prevents the recursion to exit prematurely due to an
empty response. As we want to avoid searching on a larger scale after we
found a location, we only search as long as the highest index found so far
belongs to the dummy entry. This is done with the ORDER BY and the id0 checks.
We limit the maximum amount of results to 4, as we want to process at most 4
levels of search (initial value + 3 accuracy levels). If exactly 1 or 2
objects are found during the 100m search (or exactly 1 during the 1km search),
the query will still execute the search for the next lower accuracy level.
This should happen very rarely and there is no easy way around that to
my knowledge.
*/
WITH RECURSIVE cte(id0, scale) AS (
    VALUES(0, 1)
    UNION
    SELECT
        id, (scale * 10)
    FROM
        locations_index, cte
    WHERE
        maxLat  >= (%s - scale * 0.00089831117499101688825) AND
        minLat  <= (%s + scale * 0.00089831117499101688825) AND
        maxLong >= (%s - scale * %s) AND
        minLong <= (%s + scale * %s) AND
        id0 == 0 AND
        scale <= 100
    ORDER BY id DESC
    LIMIT 4
)
SELECT id0, scale, %s, %s FROM cte ORDER BY id0 DESC LIMIT 1;
\n
