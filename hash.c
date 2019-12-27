#include <stdlib.h>
#include <stdint.h>

typedef struct {
    int size;
    uint64_t *keys;
    int **values;
} hash_t;
 
hash_t *hash_new (int size) {
    hash_t *h = calloc(1, sizeof (hash_t));
    h->keys = calloc(size, sizeof (uint64_t));
    h->values = calloc(size, sizeof (int *));
    h->size = size;
    return h;
}
 
int hash_index (hash_t *h, uint64_t key) {
    int i = (int) key % h->size;
    while (h->keys[i] && h->keys[i] != key)
        i = (i + 1) % h->size;
    return i;
}
 
void hash_insert (hash_t *h, uint64_t key, int *value) {
    int i = hash_index(h, key);
    h->keys[i] = key;
    h->values[i] = value;
}
 
int *hash_lookup (hash_t *h, uint64_t key) {
    int i = hash_index(h, key);
    return h->values[i];
}

int hash_delete (hash_t *h, uint64_t key) {
    int i = hash_index(h, key);
    h->keys[i] = 0;
    h->values[i] = 0;
    return 0;
}
