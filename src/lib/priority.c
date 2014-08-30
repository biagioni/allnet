/* priority.c: priorities of received packets, for use throughout AllNet */
/* includes operations on fractions */

#include <stdio.h>

#include "priority.h"

void print_fraction (int value, char * str)
{
  double v = ((double) value) / ((double) ALLNET_PRIORITY_MAX);
  if (str != NULL)
    printf ("%s: %f\n", str, v);
  else
    printf ("%f", v);
}

int power_half_fraction (int power)
{
  if (power <= 0)
    return ALLNET_PRIORITY_MAX;
  if (power >= 30)
    return 0;
  return ALLNET_PRIORITY_MAX >> power;
}

/* multiplying fractions, so compute with 64 bits, then shift down 30 bits */
int allnet_multiply (int p1, int p2)
{
  long long int product = ((long long int) p1) * ((long long int) p2);
  int result = product >> 30;
  return result;
}

static int divide (int dividend, int divisor)
{
  long long int product =
     ((long long int) ALLNET_PRIORITY_MAX) * ((long long int) dividend);
  long long int result = product / divisor;
  return (int) result;
}

/* if n1 < n2,  returns n1 / n2 */
/* if n1 >= n2, returns ALLNET_PRIORITY_MAX */
int allnet_divide (int n1, int n2)
{
  if (n1 >= n2)
    return ALLNET_PRIORITY_MAX;
  return divide (n1, n2);
}

int compute_priority (int size, int sbits, int dbits,
                      int hops_already, int hops_max,
                      int social_distance, int rate_fraction, int cacheable)
{
  int debug = 0;
  if (debug)
    printf ("compute_priority (%d, %d, %d, %d, %d, %d, %d)\n",
            size, sbits, dbits, hops_already,
            hops_max, social_distance, rate_fraction);
  if (social_distance <= 1)
    return ALLNET_PRIORITY_FRIENDS_HIGH;
  /* compute Ps = 2^(1-social_distance).
   * So for d == 2, Ps = 0.5, for d == 3, Ps = 0.25, etc */
  int social_priority = power_half_fraction (social_distance - 1);
  if (debug) print_fraction (social_priority, "social");

  /* For Pm and Ph 1/m heavily prioritizes short-distance traffic, and
   * and 1 - h/m gives local traffic a slight edge */
  int hops_carried_priority = ALLNET_ONE_HALF;
  if (hops_already < 1)  /* should be local, but be sane anyway */
    hops_already = 1;
  if (hops_already <= 4)
    hops_carried_priority =
      ALLNET_PRIORITY_MAX - ALLNET_ONE_EIGHT * (hops_already - 1);
  if (debug) print_fraction (hops_carried_priority, "hops_carried");
  int hops_total_priority = power_half_fraction (hops_max - 1);
  if (debug) print_fraction (hops_total_priority, "hops_total");

  /* compute Pb as 1 - 2^(1-dbits).  So for dbits == 0, Pb = 1/2,
     for dbits = 1, Pb = 3/4, for dbits = 2, Pb = 7/8, etc. */
  int bits_priority = ALLNET_PRIORITY_MAX - power_half_fraction (dbits + 1);
  if (debug) print_fraction (bits_priority, "bits");

  /* Pl = 1 - r' / r, where r' is our sending rate, and r is the maximum
   * sending rate.  rate_fraction is already r' / r */
  int rate_priority = ALLNET_PRIORITY_MAX - rate_fraction;
  if (rate_priority < ALLNET_ONE_HALF) rate_priority = ALLNET_ONE_HALF;
  if (debug) print_fraction (rate_priority, "rate");

  /* combine these as 1 - (1 - Ps) * (1 - Pb * Pg * Ph * Pl) */
  int result =
    allnet_multiply
      (social_priority,
       allnet_multiply (allnet_multiply (bits_priority, rate_priority),
                        allnet_multiply (hops_carried_priority,
                                         hops_total_priority)));
  /* give a slight boost to packets that are not cacheable */
  if (! cacheable) {
    if (result >= ALLNET_PRIORITY_MAX - (ALLNET_PRIORITY_MAX / 10))
      result = ALLNET_PRIORITY_MAX;
    else
      result += result / 10;
  }
if (result <= 0) debug = 1;
  if (debug)
    printf ("compute_priority (%d, %d, %d, %d, %d, %d, %d, %d)\n",
            size, sbits, dbits, hops_already,
            hops_max, social_distance, rate_fraction, cacheable);
  if (debug)
    printf ("result %x product of %x %x %x %x %x\n",
            result, social_priority, bits_priority, rate_priority,
            hops_carried_priority, hops_total_priority);
  if (debug)
    printf ("result %d product of %d %d %d %d %d\n",
            result, social_priority, bits_priority, rate_priority,
            hops_carried_priority, hops_total_priority);
  if (debug) print_fraction (result, "resulting priority");
if (result <= 0) result = ALLNET_PRIORITY_EPSILON;
  
  return result;
}

