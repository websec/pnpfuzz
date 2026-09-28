static int id_related(const char *a, const char *b)
{
    size_t la, lb;

    if (!a || !b || !*a || !*b) return 0;
    if (_stricmp(a, b) == 0) return 1;

    la = strlen(a);
    lb = strlen(b);
    if (la > lb) {
        const char *t = a; a = b; b = t;
        { size_t s = la; la = lb; lb = s; }
    }
    /* a is now the shorter one; b must extend it at a component boundary. */
    if (_strnicmp(a, b, la) != 0) return 0;
    return b[la] == '&';
}
