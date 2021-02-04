#include <deos.h>
#include <printx.h>
#include <time.h>

#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>

int main(void)
{

  initPrintx("wolfSSL-test");
  printx("wolfSSL test starting\n");


  // taken from hello-world-timer.cpp
  struct tm starttime = { 0, 30, 12, 1, 12, 2020-1900, 0, 0, 0 };
  // startdate: Dev 1 2020, 12:30:00
  struct timespec ts_date;
  ts_date.tv_sec  = mktime(&starttime);
  ts_date.tv_nsec = 0LL;
  int res1 = clock_settime(CLOCK_REALTIME, &ts_date);
  // this will only take effect, if time-control is set in the xml-file
  // if not, Jan 1 1970, 00:00:00 will be the date

  int res = wolfcrypt_test(NULL);

  if (res == 0) {
	  printx("wolfcrypt Test Passed\n");
  }
  else {
	  printx("wolfcrypt Test Failed: %d\n", res);
  }

  res = benchmark_test(NULL);

  if (res == 0) {
	  printx("wolfcrypt benchmark Passed\n");
  }
  else {
	  printx("wolfcrypt benchmark Failed: %d\n", res);
  }


  while (1) {
	    waitUntilNextPeriod();
  }

  return 0;
}
