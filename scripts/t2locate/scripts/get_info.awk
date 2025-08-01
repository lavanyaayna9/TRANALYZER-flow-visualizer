{
    switch ($2)
    {
        case 10:   accuracy = "100m"; break;
        case 100:  accuracy =  "1km"; break;
        case 1000: accuracy = "10km"; break;
        default:   accuracy = "-";    break;
    }

    printf (query, $3, $4, accuracy, $1);
}
