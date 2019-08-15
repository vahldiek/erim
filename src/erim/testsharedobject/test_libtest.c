__attribute__((weak)) void set_var(unsigned long * var) {
  *var = 0xAAAAAAAA;
}

__attribute__((weak)) unsigned long read_var(unsigned long * var, unsigned long add) {
  return *var + add;
}
