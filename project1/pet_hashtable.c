/*
  Copyright (c) 2002, 2004, Christopher Clark
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  * Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  * Neither the name of the original author; nor the names of any contributors
  may be used to endorse or promote products derived from this software
  without specific prior written permission.


  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>


#include "pet_hashtable.h"

struct hash_entry {
	uintptr_t           key;
	uintptr_t           value;
	uint32_t            hash;
	struct hash_entry * next;
};

struct pet_hashtable {
	struct hash_entry ** table;

	uint32_t table_length;
	uint32_t entry_count;
	uint32_t load_limit;
	uint32_t prime_index;

	uint32_t (*hash_fn)    (uintptr_t key);
	int      (*eq_fn)      (uintptr_t key1, uintptr_t key2);
	void     (*val_free_fn)(uintptr_t val);
	void     (*key_free_fn)(uintptr_t key);
};


#define HTABLE_FREE(x) free(x)
#define HTABLE_CALLOC(cnt, size) calloc(cnt, size)
/* HASH FUNCTIONS */

static inline uint32_t
do_hash(struct pet_hashtable * htable, uintptr_t key)
{
	/* Aim to protect against poor hash functions by adding logic here
	 * - logic taken from java 1.4 hashtable source */
	uint32_t i = htable->hash_fn(key);

	i += ~(i << 9);
	i ^= ((i >> 14) | (i << 18)); /* >>> */
	i += (i << 4);
	i ^= ((i >> 10) | (i << 22)); /* >>> */

	return i;
}

#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001ULL


uint32_t
pet_hash_u32(uintptr_t val)
{
	uint32_t hash = val;

	hash *= GOLDEN_RATIO_PRIME_32;

	return hash;
}

uint32_t
pet_hash_ptr(uintptr_t val)
{
	uintptr_t hash = val;
	uintptr_t n    = hash;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	n    <<= 18;
	hash -=  n;
	n    <<= 33;
	hash -=  n;
	n    <<= 3;
	hash +=  n;
	n    <<= 3;
	hash -=  n;
	n    <<= 4;
	hash +=  n;
	n    <<= 2;
	hash +=  n;

	/* High bits are more random, so use them. */
	return (uint32_t)(hash >> 32);
}

int
pet_cmp_ptr(uintptr_t val1, 
			uintptr_t val2)
{
	return (val1 == val2);
}

/* HASH GENERIC MEMORY BUFFER */
/* ELF HEADER HASH FUNCTION */
uint32_t
pet_hash_buffer(uint8_t  * msg, 
                uint32_t   length)
{
	uint32_t hash = 0;
	uint32_t temp = 0;
	uint32_t i;

	for (i = 0; i < length; i++) {
		hash = (hash << 4) + *(msg + i) + i;

		if ((temp = (hash & 0xF0000000))) {
			hash ^= (temp >> 24);
		}

		hash &= ~temp;
	}
	return hash;
}

/* indexFor */
static inline uint32_t
indexFor(uint32_t table_length, uint32_t hash_value)
{
	return (hash_value % table_length);
};


/*
  Credit for primes table: Aaron Krowne
  http://br.endernet.org/~akrowne/
  http://planetmath.org/encyclopedia/GoodHashTablePrimes.html
*/
static const uint32_t primes[]
= { 53,        97,        193,       389,       769,       1543,     3079,
    6151,      12289,     24593,     49157,     98317,     196613,   393241,
    786433,    1572869,   3145739,   6291469,   12582917,  25165843, 50331653,
    100663319, 201326611, 402653189, 805306457, 1610612741 };

// this assumes that the max load factor is .65
static const uint32_t load_factors[]
= { 35,      64,       126,      253,      500,       1003,      2002,      3999,      7988,
    15986,   31953,    63907,    127799,   255607,    511182,    1022365,   2044731,   4089455,
    8178897, 16357798, 32715575, 65431158, 130862298, 261724573, 523449198, 1046898282 };

const uint32_t prime_table_len = sizeof(primes) / sizeof(primes[0]);

struct pet_hashtable *
pet_create_htable(uint32_t   min_size,
                  uint32_t (*hash_fn)    (uintptr_t),
                  int      (*eq_fn)      (uintptr_t, uintptr_t),
                  void     (*val_free_fn)(uintptr_t),
                  void     (*key_free_fn)(uintptr_t))
{
	struct pet_hashtable * htable      = NULL;
	uint32_t               prime_index = 0;
	uint32_t               size        = primes[0];

	/* Check requested hashtable isn't too large */
	if (min_size > (1u << 30)) {
		return NULL;
	}

	/* Enforce size as prime */
	for (prime_index = 0; prime_index < prime_table_len; prime_index++) {
		if (primes[prime_index] > min_size) {
			size = primes[prime_index];
			break;
		}
	}

	htable = (struct pet_hashtable *)HTABLE_CALLOC(1, sizeof(struct pet_hashtable));

	if (htable == NULL) {
		return NULL; /*oom*/
	}

	htable->table = (struct hash_entry **)HTABLE_CALLOC(1, sizeof(struct hash_entry *) * size);

	if (htable->table == NULL) {
		HTABLE_FREE(htable);
		return NULL; /*oom*/
	}

	htable->table_length = size;
	htable->prime_index  = prime_index;
	htable->entry_count  = 0;
	htable->hash_fn      = hash_fn;
	htable->eq_fn        = eq_fn;
	htable->val_free_fn  = val_free_fn;
	htable->key_free_fn  = key_free_fn;
	htable->load_limit   = load_factors[prime_index];

	return htable;
}

static int
hashtable_expand(struct pet_hashtable * htable)
{
	/* Double the size of the table to accomodate more entries */
	struct hash_entry ** new_table = NULL;
	struct hash_entry ** entry_ptr = NULL;
	struct hash_entry *  tmp_entry = NULL;

	uint32_t new_size = 0;
	uint32_t index    = 0;
	uint32_t i        = 0;

	/* Check we're not hitting max capacity */
	if (htable->prime_index == (prime_table_len - 1)) {
		return -1;
	}

	new_size = primes[++(htable->prime_index)];

	new_table = (struct hash_entry **)HTABLE_CALLOC(1, sizeof(struct hash_entry *) * new_size);

	if (new_table != NULL) {
		/* This algorithm is not 'stable'. ie. it reverses the list
		 * when it transfers entries between the tables */

		for (i = 0; i < htable->table_length; i++) {

			while ((tmp_entry = htable->table[i]) != NULL) {
				htable->table[i] = tmp_entry->next;
				index            = indexFor(new_size, tmp_entry->hash);
				tmp_entry->next  = new_table[index];
				new_table[index] = tmp_entry;
			}
		}

		HTABLE_FREE(htable->table);

		htable->table = new_table;
	} else {
		/* Plan B: realloc instead */

		new_table = (struct hash_entry **)realloc(htable->table, new_size * sizeof(struct hash_entry *));

		if (new_table == NULL) {
			(htable->prime_index)--;
			return -1;
		}

		htable->table = new_table;

		memset(new_table[htable->table_length], 0, new_size - htable->table_length);

		for (i = 0; i < htable->table_length; i++) {

			entry_ptr = &(new_table[i]);

			for (tmp_entry = *entry_ptr; tmp_entry != NULL; tmp_entry = *entry_ptr) {

				index = indexFor(new_size, tmp_entry->hash);

				if (i == index) {
					entry_ptr = &(tmp_entry->next);
				} else {
					*entry_ptr       = tmp_entry->next;
					tmp_entry->next  = new_table[index];
					new_table[index] = tmp_entry;
				}
			}
		}
	}

	htable->table_length = new_size;

	htable->load_limit = load_factors[htable->prime_index];

	return 0;
}

uint32_t
pet_htable_count(struct pet_hashtable * htable)
{
	return htable->entry_count;
}

int
pet_htable_insert(struct pet_hashtable * htable, uintptr_t key, uintptr_t value)
{
	/* This method allows duplicate keys - but they shouldn't be used */
	struct hash_entry * new_entry = NULL;
	uint32_t            index     = 0;

	if (++(htable->entry_count) > htable->load_limit) {
		/* Ignore the return value. If expand fails, we should
		 * still try cramming just this value into the existing table
		 * -- we may not have memory for a larger table, but one more
		 * element may be ok. Next time we insert, we'll try expanding again.*/
		hashtable_expand(htable);
	}

	new_entry = (struct hash_entry *)HTABLE_CALLOC(1, sizeof(struct hash_entry));

	if (new_entry == NULL) {
		(htable->entry_count)--;
		return -1; /*oom*/
	}

	new_entry->hash = do_hash(htable, key);
	index           = indexFor(htable->table_length, new_entry->hash);

	new_entry->key   = key;
	new_entry->value = value;

	new_entry->next      = htable->table[index];
	htable->table[index] = new_entry;

	return 0;
}

int
pet_htable_change(struct pet_hashtable * htable, uintptr_t key, uintptr_t value)
{
	struct hash_entry * tmp_entry  = NULL;
	uint32_t            hash_value = 0;
	uint32_t            index      = 0;

	hash_value = do_hash(htable, key);
	index      = indexFor(htable->table_length, hash_value);
	tmp_entry  = htable->table[index];

	while (tmp_entry != NULL) {
		/* Check hash value to short circuit heavier comparison */
		if ((hash_value == tmp_entry->hash) && (htable->eq_fn(key, tmp_entry->key))) {

			if (htable->val_free_fn) {
				htable->val_free_fn(tmp_entry->value);
			}

			tmp_entry->value = value;
			return 0;
		}

		tmp_entry = tmp_entry->next;
	}
	return -1;
}

int
pet_htable_inc(struct pet_hashtable * htable, uintptr_t key, uintptr_t value)
{
	struct hash_entry * tmp_entry  = NULL;
	uint32_t            hash_value = 0;
	uint32_t            index      = 0;

	hash_value = do_hash(htable, key);
	index      = indexFor(htable->table_length, hash_value);
	tmp_entry  = htable->table[index];

	while (tmp_entry != NULL) {
		/* Check hash value to short circuit heavier comparison */
		if ((hash_value == tmp_entry->hash) && (htable->eq_fn(key, tmp_entry->key))) {

			tmp_entry->value += value;
			return 0;
		}

		tmp_entry = tmp_entry->next;
	}

	return -1;
}

int
pet_htable_dec(struct pet_hashtable * htable, uintptr_t key, uintptr_t value)
{
	struct hash_entry * tmp_entry  = NULL;
	uint32_t            hash_value = 0;
	uint32_t            index      = 0;

	hash_value = do_hash(htable, key);
	index      = indexFor(htable->table_length, hash_value);
	tmp_entry  = htable->table[index];

	while (tmp_entry != NULL) {
		/* Check hash value to short circuit heavier comparison */
		if ((hash_value == tmp_entry->hash) && (htable->eq_fn(key, tmp_entry->key))) {

			tmp_entry->value -= value;
			return 0;
		}

		tmp_entry = tmp_entry->next;
	}
	return -1;
}

/* returns value associated with key */
void *
pet_htable_search(struct pet_hashtable * htable, uintptr_t key)
{
	struct hash_entry * cursor     = NULL;
	uint32_t            hash_value = 0;
	uint32_t            index      = 0;

	hash_value = do_hash(htable, key);
	index      = indexFor(htable->table_length, hash_value);
	cursor     = htable->table[index];

	while (cursor != NULL) {
		/* Check hash value to short circuit heavier comparison */
		if ((hash_value == cursor->hash) && (htable->eq_fn(key, cursor->key))) {

			return (void *)cursor->value;
		}

		cursor = cursor->next;
	}

	return NULL;
}

/* returns value associated with key */
uintptr_t
pet_htable_cond_remove(struct pet_hashtable * htable,
                       uintptr_t              key,
                       bool (*cond_func)(uintptr_t value))
{
	/* TODO: consider compacting the table when the load factor drops enough,
	 *       or provide a 'compact' method. */

	struct hash_entry *  cursor    = NULL;
	struct hash_entry ** entry_ptr = NULL;

	uintptr_t value      = 0;
	uint32_t  hash_value = 0;
	uint32_t  index      = 0;

	hash_value = do_hash(htable, key);
	index      = indexFor(htable->table_length, hash_value);
	entry_ptr  = &(htable->table[index]);
	cursor     = *entry_ptr;

	while (cursor != NULL) {

		/* Check hash value to short circuit heavier comparison */
		if ((hash_value == cursor->hash) && (htable->eq_fn(key, cursor->key))) {
			if (cond_func != NULL && cond_func(cursor->value) != true) {
				return (uintptr_t)NULL;
			}

			*entry_ptr           = cursor->next;
			htable->entry_count -= 1;
			value                = cursor->value;

			if (htable->key_free_fn) {
				htable->key_free_fn(cursor->key);
			}

			HTABLE_FREE(cursor);

			return value;
		}

		entry_ptr = &(cursor->next);
		cursor    = cursor->next;
	}

	return (uintptr_t)NULL;
}

uintptr_t
pet_htable_remove(struct pet_hashtable * htable, uintptr_t key)
{
	return pet_htable_cond_remove(htable, key, NULL);
}

/* destroy */
void
pet_free_htable(struct pet_hashtable * htable)
{
	struct hash_entry *  cursor = NULL;
	struct hash_entry *  tmp    = NULL;
	struct hash_entry ** table  = htable->table;
	uint32_t             i      = 0;

 
	for (i = 0; i < htable->table_length; i++) {
		cursor = table[i];
	
		while (cursor != NULL) {
	    
			tmp    = cursor;
			cursor = cursor->next;
	    
			if (htable->key_free_fn) {
				htable->key_free_fn(tmp->key);
			}

			if (htable->val_free_fn) {
				htable->val_free_fn(tmp->value);
			}
	    
			HTABLE_FREE(tmp);
		}
	}
    
	HTABLE_FREE(htable->table);
	HTABLE_FREE(htable);
}

/* HASH TABLE ITERATORS */

struct pet_hashtable_iter *
pet_htable_create_iter(struct pet_hashtable * htable)
{
	//    uint32_t i            = 0;
	uint32_t table_length = 0;

	struct pet_hashtable_iter * iter = (struct pet_hashtable_iter *)HTABLE_CALLOC(sizeof(struct pet_hashtable_iter), 1);

	if (iter == NULL) {
		return NULL;
	}

	iter->htable = htable;
	iter->entry  = NULL;
	iter->parent = NULL;
	table_length = htable->table_length;
	iter->index  = table_length;

	/*

	  if (htable->entry_count == 0) {
	  return iter;
	  }
    
	  for (i = 0; i < table_length; i++) {

	  if (htable->table[i] != NULL) {
	  iter->entry = htable->table[i];
	  iter->index = i;
	  break;
	  }
	  }
	*/

	return iter;
}

void
pet_htable_free_iter(struct pet_hashtable_iter * iter)
{
	HTABLE_FREE(iter);
}

uintptr_t
pet_htable_get_iter_key(struct pet_hashtable_iter * iter)
{
	return iter->entry->key;
}

uintptr_t
pet_htable_get_iter_value(struct pet_hashtable_iter * iter)
{
	return iter->entry->value;
}

/* advance - advance the iterator to the first/next element
 *           returns zero if advanced to end of table
 */
int
pet_htable_iter_advance(struct pet_hashtable_iter * iter)
{
	uint32_t i            = 0;
	uint32_t j            = 0;
	uint32_t table_length = iter->htable->table_length;;

	struct hash_entry ** table = NULL;
	struct hash_entry *  next  = NULL;

	if (iter->entry == NULL) {
		for (i = 0; i < table_length; i++) {
			if (iter->htable->table[i] != NULL) {
				iter->entry = iter->htable->table[i];
				iter->index = i;
				break;
			}
		}

		return (iter->entry != NULL);
	}

	next = iter->entry->next;

	if (next != NULL) {
		iter->parent = iter->entry;
		iter->entry  = next;
		return 1;
	}

	iter->parent = NULL;

	if (table_length <= (j = ++(iter->index))) {
		iter->entry = NULL;
		return 0;
	}

	table = iter->htable->table;

	while ((next = table[j]) == NULL) {

		if (++j >= table_length) {
			iter->index = table_length;
			iter->entry = NULL;
			return 0;
		}
	}

	iter->index = j;
	iter->entry = next;

	return 1;
}

/* remove - remove the entry at the current iterator position
 *          and advance the iterator, if there is a successive
 *          element.
 *          If you want the value, read it before you remove:
 *          beware memory leaks if you don't.
 *          Returns zero if end of iteration. */
int
pet_htable_iter_remove(struct pet_hashtable_iter * iter)
{
	struct hash_entry * remember_entry  = NULL;
	struct hash_entry * remember_parent = NULL;
	int                 ret;

	/* Do the removal */
	if ((iter->parent) == NULL) {
		iter->htable->table[iter->index] = iter->entry->next; /* element is head of a chain */
	} else {
		iter->parent->next = iter->entry->next; /* element is mid-chain */
	}

	/* itr->e is now outside the hashtable */
	remember_entry = iter->entry;
	iter->htable->entry_count -= 1;

	if (iter->htable->key_free_fn) {
		iter->htable->key_free_fn(remember_entry->key);
	}

	/* Advance the iterator, correcting the parent */
	remember_parent = iter->parent;
	ret             = pet_htable_iter_advance(iter);

	if (iter->parent == remember_entry) {
		iter->parent = remember_parent;
	}

	HTABLE_FREE(remember_entry);
	return ret;
}

/* returns zero if not found */
int
pet_htable_iter_search(struct pet_hashtable_iter * iter,
                       struct pet_hashtable      * htable,
                       uintptr_t                   key)
{
	struct hash_entry * entry  = NULL;
	struct hash_entry * parent = NULL;

	uint32_t hash_value = 0;
	uint32_t index      = 0;

	hash_value = do_hash(htable, key);
	index      = indexFor(htable->table_length, hash_value);

	entry  = htable->table[index];
	parent = NULL;

	while (entry != NULL) {

		/* Check hash value to short circuit heavier comparison */
		if ((hash_value == entry->hash) && (htable->eq_fn(key, entry->key))) {

			iter->index  = index;
			iter->entry  = entry;
			iter->parent = parent;
			iter->htable = htable;

			return 1;
		}

		parent = entry;
		entry  = entry->next;
	}

	return 0;
}
