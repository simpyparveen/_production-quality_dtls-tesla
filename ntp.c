/*
// Created by user on 07/01/20.

 NTP implementation
   handles arithmetic usage and creation
   of NTP timestamps
*/


//#include "NTP.h"
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <math.h>
const uint64_t FRAC_MAX = 1000000; //microseconds
/** Here we change timeval to microseconds and show in double. Converting them to seconds doesn't work properly. Check again!! */
#define NTP_TO_DOUBLE(a) ((double)((double)(a.tv_sec)/FRAC_MAX + (double)((a.tv_usec))))//((double)( (double)a.tv_sec+(double)((a.tv_usec)/FRAC_MAX) )) //converts to seconds




/*#define DOUBLE_TO_NTP(a,b){ \
         b.tv_sec = (int)a; \
         b.tv_usec = (a - b.tv_sec)* 1000000; \
         }





///Ref : https://github.com/ratschlab/dss/blob/master/tv.c
void d2tv(double x, struct timeval *tv)
{
    tv->tv_sec = x;
    tv->tv_usec = (x - (double)tv->tv_sec) * 1000.0 * 1000.0 + 0.5;
}

*/


/**
 * Compute integer multiple of given struct timeval.
 *
 * \param mult The integer value to multiply with.
 * \param tv The timevalue to multiply.
 *
 * \param result Contains \a mult * \a tv on return.
 */
void tv_scale(const unsigned long mult, const struct timeval *tv,
              struct timeval *result)
{
    result->tv_sec = mult * tv->tv_sec;
    result->tv_sec += tv->tv_usec * mult / 1000 / 1000;
    result->tv_usec = tv->tv_usec * mult % (1000 * 1000);
}

/**
 * Compute a fraction of given struct timeval.
 *
 * \param divisor The integer value to divide by.
 * \param tv The timevalue to divide.
 * \param result Contains (1 / mult) * tv on return.
 */
struct timeval tv_divide(const unsigned long divisor, struct timeval tv)
{
    struct timeval result;
    uint64_t x = ((uint64_t)tv.tv_sec * 1000 * 1000 + tv.tv_usec) / divisor;

    result.tv_sec = x / 1000 / 1000;
    result.tv_usec = x % (1000 * 1000);
    return result;
}



//replace NTP_t with timeval

/*
typedef struct {
    uint32 seconds;
    uint32 fraction;
} NTP_t;

 struct timeval {
    time_t      tv_sec;     // seconds
    suseconds_t tv_usec;    // microseconds
};


//Traditionally, the fields of struct timeval were of type long.


 */


////write from timeval to buf
//void NTP_write(void *buf,struct timeval a){
//    memcpy(buf,(a.tv_sec),sizeof(uint64_t));
//    buf+=sizeof(uint64_t);
//    memcpy(buf,(a.tv_usec),sizeof(uint64_t));
//}
//
////read from buf to timeval
//void NTP_read(void *buf,struct timeval *a){
//    memcpy(&(a->tv_sec),buf,sizeof(uint64_t));
//    buf+=sizeof(uint64_t);
//    memcpy(&(a->tv_usec),buf,sizeof(uint64_t));
//}
////
//void NTP_now(struct timeval c){
//    struct timeval tv;
//    if(gettimeofday(&tv,NULL)){
//        printf("NTP, fatal error");exit(-1);
//    }
//    c.tv_sec=tv.tv_sec;
//    c.tv_usec=tv.tv_usec;
//}



///absolute value of the difference of two times
///|a-b|
///a-b
struct timeval NTP_dif(struct timeval a,struct timeval b){
    struct timeval ret;
    double time1=NTP_TO_DOUBLE(a);
    double time2=NTP_TO_DOUBLE(b);

    time1 = fabs(time1 - time2);
    ret.tv_sec = (uint64_t)time1;
    time1 -= ret.tv_sec;
    ret.tv_usec = time1*FRAC_MAX;
    return ret;
}

//void NTP_mult(struct timeval *a,uint32_t m){
//    double time=NTP_TO_DOUBLE(a);
//    time*=m;
//    a.tv_sec = (uint32_t)time;
//    time = time - a.tv_sec;
//    a.tv_usec = time*FRAC_MAX;
//}

///// a+b
struct timeval NTP_add(struct timeval a,struct timeval b){
    long long frac;
    struct timeval ret;
    frac = (long long)a.tv_usec + (long long)b.tv_usec;
    ret.tv_sec = a.tv_sec+b.tv_sec;
    ret.tv_sec += (frac >> 32);
    ret.tv_usec = (long)frac;
    return ret;
}


/////a-b
struct timeval NTP_sub(struct timeval a,struct timeval b){
    struct timeval ret;
    double time1=NTP_TO_DOUBLE(a);
    double time2=NTP_TO_DOUBLE(b);
    time1-=time2;
    ret.tv_sec=(uint64_t)time1;
    time1-= ret.tv_sec;
    ret.tv_usec = time1*FRAC_MAX;
    return ret;
}


///a div b(discrete)
uint64_t NTP_div(struct timeval a,struct timeval b){
    double time = NTP_TO_DOUBLE(a);
    double time2 = NTP_TO_DOUBLE(b);
    printf("\ntime :%lf\n",time);
    printf("\ntime2 :%lf\n",time2);
    printf("\nNTP_div :%lf\n",(uint64_t)(time/time2));
    return ((uint64_t)(time / time2));
}


///  a / b, non integer
struct timeval NTP_divd(struct timeval a, double b){
    struct timeval ret;
    double time=NTP_TO_DOUBLE(a);
    time/=b;
    ret.tv_sec = (uint64_t)time;
    time = time - ret.tv_sec;
    ret.tv_usec = time*FRAC_MAX;
    return ret;
}


///NTP time from milliseconds
struct timeval NTP_fromMillis(uint64_t millis){
    struct timeval ret;
    ret.tv_sec=millis;
    ret.tv_usec=0;

    //NTP_divd(&ret,1000.0);
    double time=NTP_TO_DOUBLE(ret);
    time/=1000;
    ret.tv_sec = (uint64_t)time;
    time = time - ret.tv_sec;
    ret.tv_usec = time*FRAC_MAX;

    return ret;
}

