#include <stdio.h>
#include <string.h>
#include <math.h>
int main()
{
    long long int n, d, i, l, j, k, e;
    long long int median;
    long int notifict = 0;
    scanf("%lld", &n);
    scanf("%lld", &d);
    long long int a[n];
    long long int b[d]; //9 5;2 3 4 2 3 6 8 4 5

    for (i = 0; i < n; i++)
    {
        scanf("%lld", &a[i]);
    }
    for (i = 0; i < n - d; i++)
    {
        k = d;
        for (l = 0, j = i; l < d, j < d + i; l++, j++)
        {
            b[l] = a[j];
        }
       for (l = 0; l < d; l++)
        {
            printf("the seq. chosen is %lld\n", b[l]);
        }
        for (j = 0; j < k; j++)
        {
            k = k - 1;
            for (l = 0; l < k; l++)
            {
                if (b[l] > b[l + 1])
                {
                    e = b[l + 1];
                    b[l + 1] = b[l];
                    b[l] = e;
                }
                else
                {
                    continue;
                }
            }
        }
       for (l = 0; l < d; l++)
        {
            printf("seq.arrang :%lld\n", b[l]);
        }
        if (d % 2 == 0)
        {

            median = b[d / 2] + b[(d / 2) + 1];
            printf("median is %lld\n",median);
            printf("a[d+i] is %lld\n",a[d+i]);
            if (a[d + i]>=2* median)
            {
                notifict = notifict + 1;
            }
            else
            {
                notifict = notifict;
            }
        }
        else
        {
 
            median = b[d / 2];
            printf("%lld\n",median);
            printf("%lld\n",a[d+i]);
            if (a[d + i] >= 2*median)
            {
                notifict = notifict + 1;
            }
            else
            {
                notifict = notifict;
            }
        }
    }
    printf("%lld\n", notifict);
}