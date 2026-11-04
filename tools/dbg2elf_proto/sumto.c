/* sumto.c: the source of the z80 ELF line-table test */
int total;

int add(int a, int b)
{
    return a + b;
}

int main(void)
{
    int i;
    total = 0;
    for (i = 1; i <= 4; i++)
        total = add(total, i);
    return 0;
}
