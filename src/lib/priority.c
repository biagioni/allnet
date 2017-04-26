/* priority.c: priorities of received packets, for use throughout AllNet */
/* includes operations on fractions */

#include <stdio.h>
#include <stdint.h>

#include "priority.h"

void print_fraction (unsigned int value, char * str)
{
  double v = ((double) value) / ((double) ALLNET_PRIORITY_MAX);
  if (str != NULL)
    printf ("%s: %f\n", str, v);
  else
    printf ("%f", v);
}

unsigned int power_half_fraction (unsigned int power)
{
  if (power <= 0)
    return ALLNET_PRIORITY_MAX;
  if (power >= 30)
    return 0;
  return ALLNET_PRIORITY_MAX >> power;
}

/* multiplying fractions, so compute with 64 bits, then shift down 30 bits */
unsigned int allnet_multiply (unsigned int p1, unsigned int p2)
{
  uint64_t product = ((uint64_t) p1) * ((uint64_t) p2);
  int result = (int)(product >> 30);
  return result;
}

static unsigned int divide (unsigned int dividend, unsigned int divisor)
{
  uint64_t product =
     ((uint64_t) ALLNET_PRIORITY_MAX) * ((uint64_t) dividend);
  uint64_t result = product / divisor;
  return (unsigned int) result;
}

/* if n1 < n2,  returns n1 / n2 */
/* if n1 >= n2, returns ALLNET_PRIORITY_MAX */
unsigned int allnet_divide (unsigned int n1, unsigned int n2)
{
  if (n1 >= n2)
    return ALLNET_PRIORITY_MAX;
  return divide (n1, n2);
}

unsigned int compute_priority (unsigned int size,
                               unsigned int sbits, unsigned int dbits,
                               unsigned int hops_already, unsigned int hops_max,
                               unsigned int social_distance,
                               unsigned int rate_fraction, int cacheable)
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
  int hops_total_priority = 
    (hops_max > 0) ? power_half_fraction (hops_max - 1)
                   : ALLNET_PRIORITY_EPSILON;  /* illegal packet anyway */
  if (hops_total_priority <= 0) /* multiplication below is 0, make epsilon */
    hops_total_priority = ALLNET_PRIORITY_EPSILON;
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
if ((result <= 0) && (hops_max < 15) && (hops_max > 0)) debug = 1;
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

