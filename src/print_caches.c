/* print the contents of the caches */

int main (int argc, char ** argv)
{
  extern void print_caches (int print_msgs, int print_acks);
  extern void init_log (char * module_name);

  init_log ("print_caches");
  print_caches (5, 1);
  return 0;
}
