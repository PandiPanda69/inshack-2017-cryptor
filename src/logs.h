#ifndef __LOGS_H__
#define __LOGS_H__

#ifdef DEBUG
    #include <stdio.h>
    #define __DEBUG(__str)  printf("%s :: %s\n", __FILE__, __str);
#else
    #define __DEBUG(__str)     ;
#endif

#endif
