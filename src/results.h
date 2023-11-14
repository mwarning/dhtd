#ifndef _RESULTS_H
#define _RESULTS_H

#define MAX_RESULTS_PER_SEARCH 500

void results_add(const uint8_t id[], int af, const void *data, size_t data_len);
void results_print(FILE *fp, const uint8_t id[]);
void results_clear(const uint8_t id[]);
unsigned results_count(const uint8_t id[]);

#endif // _RESULTS_H
