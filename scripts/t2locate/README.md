t2locate
========

Description
-----------

Get a descriptive location based on latitude/longitude coordinates.

Dependencies
------------

bash, wget, gcc, awk, sed, unzip

Setup
-----

Before you can use this tool, you need to setup the database. To do that, run
the `update_db` script. This will take several minutes. Whenever you would like
to update the location database, simply run the script again. Location data is
automatically downloaded from [geonames.org](http://download.geonames.org/export/dump/allCountries.zip).

Usage
-----

To use the tool, run the `t2locate` script and provide the latitude/longitude
to look up in degrees as command line arguments:

```
$ ./t2locate 34.34 56.56  # latitude longitude
```

Alternatively, you can provide a list of coordinates via a file:

```
$ cat loc.txt
34.34 <tab> 56.56
56.56 <tab> 34.34
$ ./t2locate -i loc.txt
...
$
```

Or via `stdin`:

```
$ ./t2locate
34.34 <tab> 56.56
56.56 <tab> 34.34
<CTRL+D>
...
$
```

See `t2locate --help` for more information on how to use it:

```
$ ./t2locate --help
```

Output
------

The output will be in the following format, separated by tabs (unless
specified otherwise):

```
Latitude Longitude Country Admin1 Admin2 Admin3 Admin4 Name Accuracy
```

This will return a point of interest that is close to the coordinates you
supplied. It does not have to be the closest point of interest! It's just
the first one we found within the accuracy range. Possible values for the
accuracy are 100m, 1km and 10km. If there is no point of interest within
10km, the script will return a `"-"` in every column. Latitude/Longitude
are the original values entered, not the coordinates of the result.
Admin1-4 are the next smaller administrative regions below the country
level. The meaning of those is different for each country. They are mostly
similar to State -> District -> Town. Admin4 is often missing.

Troubleshooting
---------------

What to do if this breaks:

 - It's always a good start to simply run the `update_db` script again
 - If you don't have `gcc` installed or want to use another C compiler,
   replace it in `update_db` -> `COMPILER`
 - If the `sqlite3` download fails because the file doesn't exist anymore,
   get a direct link to the most recent `sqlite-amalgamation` archive and
   put its URL into `update_db` -> `SQLITE_URL`
 - If the download from `geonames.org` fails because it can't find the file
   anymore, search for the direct link to the "All Countries" archive and put
   its URL into `update_db` -> `GEONAMES_URL`
 - If `geonames.org` changed their data format, adjust the schema in
   `scripts/db.schema` accordingly. That's hopefully enough.
 - If `geonames.org` doesn't exist anymore, you're out of luck...
