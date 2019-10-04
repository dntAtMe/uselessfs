#include <stdarg.h>
#include <time.h>
#include <stdio.h>

#include "log.h"

#ifndef LOG
void log_format(const char *tag, const char *msg, va_list args) {}
#else

void log_format(const char *tag, const char *msg, va_list args)
{
    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0';
    printf("%s [%s] ", date, tag);
    vprintf(msg, args);     
    printf("\n");
}
#endif
void log_error(const char *message, ...)
{
    va_list args;   
    va_start(args, message);    
    log_format("\033[01;31merror\033[0m", message, args);     
    va_end(args);
}

void log_warning(const char *message, ...)
{
    va_list args;   
    va_start(args, message);    
    log_format("\033[01;33mwarning\033[0m", message, args);     
    va_end(args);
}
void log_info(const char *message, ...)
{
    va_list args;   
    va_start(args, message);    
    log_format("\033[01;32minfo\033[0m", message, args);     
    
    va_end(args);
}
void log_debug(const char *message, ...)
{
    va_list args;   
    va_start(args, message);    
    log_format("debug", message, args);     
    va_end(args);
}
