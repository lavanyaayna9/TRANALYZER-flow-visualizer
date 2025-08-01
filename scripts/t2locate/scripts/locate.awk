$1 !~ /^#/ {
    long_delta = 360 / (400075 * cos(atan2(0, -1) * $1 / 180));
    printf (query, $1, $1, $2, long_delta, $2, long_delta, $1, $2);
}
