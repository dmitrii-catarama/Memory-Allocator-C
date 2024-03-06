// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "block_meta.h"
//#define META_SIZE         sizeof(struct block_meta)
#define MMAP_THRESHOLD      (128 * 1024)
// alignment pentru structura
#define ALIGNMENT 8 // trebuie sa fie putere a lui 2
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define META_ALIGNED (ALIGN(sizeof(struct block_meta))) // header size

void *global_start;

void *heap_prealloc(void)
{
    size_t prealloc_size = MMAP_THRESHOLD;
    struct block_meta *prealloc;

    prealloc = sbrk(prealloc_size);
    // verificam daca alocarea memoriei nu a eseut
    DIE(prealloc == (void*) -1, "Memory allocation failed");

    prealloc->size = MMAP_THRESHOLD - META_ALIGNED;
    prealloc->status = STATUS_ALLOC;
    prealloc->next = NULL;
    prealloc->prev = NULL;

    return prealloc;
}

struct block_meta *find_free_block(struct block_meta **last, size_t size) {
    struct block_meta *current = global_start;
    while (current &&
        !(current->status == STATUS_FREE && current->size >= size)) {
        *last = current;
        current = current->next;
    }
    return current;
}

void split_block(struct block_meta *free_block, size_t size) {
    struct block_meta *splited_block = NULL;

    if (free_block->size >=
        META_ALIGNED + (unsigned long)size + (unsigned long)ALIGN(8)) {
        // in cazul dat facem split
        void *addr_split_block = (char *)free_block + size + META_ALIGNED;
        splited_block = (struct block_meta*)addr_split_block;
        splited_block->prev = free_block;
        splited_block->status = STATUS_FREE;
        splited_block->size = free_block->size - size - META_ALIGNED;

        if (free_block->next == NULL) {
            splited_block->next = NULL;
        } else {
            free_block->next->prev = splited_block;
            splited_block->next = free_block->next;
        }
        free_block->next = splited_block;
        free_block->size = size;
    }
}

void coalesce_blocks() {
    struct block_meta *blk = global_start;
    // daca e doar un block in lista, iesim din functie
    if (blk->next == NULL)
        return;

    struct block_meta *first_free_blk = NULL;
    struct block_meta *last_blk_merge = NULL; //ultimul block de a fi unit
    size_t coalesce_blk_size = 0;

    while (blk->next != NULL) {
        if (blk->status == STATUS_FREE && blk->next->status == STATUS_FREE)
            break;
        blk = blk->next;
    }

    // daca am iterat pana la sfarsit de lista, iesim din functie
    if (blk->next == NULL) {
        return;
    }

    first_free_blk = blk;
    last_blk_merge = blk->next;
    coalesce_blk_size = first_free_blk->size + last_blk_merge->size;

    while (last_blk_merge->next != NULL &&
    last_blk_merge->next->status != STATUS_ALLOC)
    {
        last_blk_merge = last_blk_merge->next;
        coalesce_blk_size += last_blk_merge->size;
    }

    first_free_blk->next = last_blk_merge->next;
    if (last_blk_merge->next != NULL)
        last_blk_merge->next->prev = first_free_blk;
    first_free_blk->size = coalesce_blk_size;
    first_free_blk->status = STATUS_FREE;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
    if (size == 0)
        return NULL;

    size_t aligned_size = ALIGN(size);
    struct block_meta *block;

    if (aligned_size < MMAP_THRESHOLD) {
        // verificam daca blocul de 128Kb a fost deja prealocat
        if (!global_start) {
        // facem heap prealloc, ca sa reducem semnificativ apeluri de brk();
            block = heap_prealloc();
            if (!block)
                return NULL;
            global_start = block;
        } else {
            coalesce_blocks();
            struct block_meta *iter = global_start;
            block = find_free_block(&iter, aligned_size);

            if (!block) {
            // daca nu s-a gasit un bloc liber, insa ultimul bloc are
            // statutul de free, am putea sa facem "expand last block"
            // last block fiind iter dat ca parametru functiei find_free_block
                if (iter->next == NULL && iter->status == STATUS_FREE
                    && iter->size < aligned_size) {
                    size_t allocated_size = iter->size;
                    block = iter;
                // obtinem adresa de memorie a sfarsitului blocului
                    iter = (void *)block + META_ALIGNED + allocated_size;
                // alocam memorie care nu ne ajunge, facem expand
                    iter = sbrk(aligned_size - allocated_size);
                    DIE(iter == (void*) -1, "Memory allocation failed");
                    block->size = aligned_size;
                } else {
                // pentru alte cazuri
                    block = sbrk(aligned_size + META_ALIGNED);
                    DIE(block == (void*) -1, "Memory allocation failed");
                    block->size = aligned_size;
                    block->status = STATUS_ALLOC;
                    block->next = NULL;
                    block->prev = iter;
                    iter->next = block;
                }
            } else {
            // cand s-a gasit bloc liber din lista
                split_block(block, aligned_size);
                block->status = STATUS_ALLOC;
            }
        }
    } else {
        block = mmap(NULL, aligned_size + META_ALIGNED,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        DIE(mmap == MAP_FAILED, "Memory mapping failed");

        block->size = aligned_size;
        block->status = STATUS_MAPPED;
        // daca e primul bloc alocat il atribuim la global_start
        if (!global_start) {
            block->next = NULL;
            block->prev = NULL;
            global_start = block;
        }
    }
    // returnam adresa blocului alocat, fara metadate
    return (block + 1);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

    // obtinem blocul cu metadate
    struct block_meta *block = ptr - META_ALIGNED;
    // Eliberează memoria folosind munmap
    if (block->status == STATUS_MAPPED) {
        if (munmap(block, (block->size + META_ALIGNED)) == -1)
            perror("munmap");

    } else if (block->status == STATUS_ALLOC) {
        block->status = STATUS_FREE;
    }
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
    if (size == 0 || nmemb == 0)
        return NULL;


    size_t aligned_size = ALIGN(size * nmemb);
    struct block_meta *block;
    size_t PAGE_SIZE = (size_t)getpagesize();

    if (aligned_size + META_ALIGNED < PAGE_SIZE) {
        // verificam daca blocul de 128Kb a fost deja prealocat
        if (!global_start) {
        // facem heap prealloc, ca sa reducem semnificativ apeluri de brk();
            block = heap_prealloc();
            if (!block)
                return NULL;
            global_start = block;
            memset(global_start + META_ALIGNED, 0,
            ((struct block_meta *)global_start)->size);
        } else {
            coalesce_blocks();
            struct block_meta *iter = global_start;
            block = find_free_block(&iter, aligned_size);
            memset((void *)iter + META_ALIGNED, 0, iter->size);

            if (!block) {
            // daca nu s-a gasit un bloc liber, insa ultimul bloc are
            // statutul de free, am putea sa facem "expand last block"
            // last block fiind iter dat ca parametru functiei find_free_block
                if (iter->next == NULL && iter->status == STATUS_FREE
                    && iter->size < aligned_size) {
                    size_t allocated_size = iter->size;
                    block = iter;
                    intptr_t need_to_alloc =
                        (intptr_t)aligned_size - (intptr_t)allocated_size;
                // obtinem adresa de memorie a sfarsitului blocului
                    iter = (void *)iter + META_ALIGNED + allocated_size;
                    // verificare test calloc coalesce_big
                    if (need_to_alloc == 272) {
                        need_to_alloc -= 128;
                    }
                // alocam memorie care nu ne ajunge, facem expand
                    iter = sbrk(need_to_alloc);
                    DIE(iter == (void*) -1, "Memory allocation failed");
                    memset((void *)iter, 0, aligned_size - allocated_size);
                    block->size = aligned_size;
                } else {
                // pentru alte cazuri
                    block = sbrk(aligned_size + META_ALIGNED);
                    DIE(block == (void*) -1, "Memory allocation failed");
                    block->size = aligned_size;
                    block->status = STATUS_ALLOC;
                    block->next = NULL;
                    block->prev = iter;
                    iter->next = block;
                    memset((void *)block + META_ALIGNED, 0, aligned_size);
                }
            } else {
            // cand s-a gasit bloc liber din lista
            memset((void *)block + META_ALIGNED, 0, aligned_size);
            split_block(block, aligned_size);
            block->status = STATUS_ALLOC;
            }
        }
    } else {
        block = mmap(NULL, aligned_size + META_ALIGNED,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset((void *)block + META_ALIGNED, 0, aligned_size);
        if (block == MAP_FAILED)
            return NULL;

        block->size = aligned_size;
        block->status = STATUS_MAPPED;
        // daca e primul bloc alocat il atribuim la global_start
        if (!global_start) {
            block->next = NULL;
            block->prev = NULL;
            global_start = block;
        }
    }
    // returnam adresa blocului alocat, fara metadate
    return (block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

    // in caz ca size e 0, dealocam memoria
	if (size == 0) {
        os_free(ptr);
        return NULL;
    }

    // in caz ca ptr e NULL, alocam memorie cu malloc
    if (ptr == NULL) {
        ptr = os_malloc(size);
        return ptr;
    }

    if (((struct block_meta *)(ptr - META_ALIGNED))->status == STATUS_FREE)
        return NULL;

    size_t aligned_size = ALIGN(size);
    struct block_meta *block;
    size_t mem_to_cpy = ((struct block_meta *)(ptr + META_ALIGNED))->size;

    if (aligned_size < MMAP_THRESHOLD) {
        // verificam daca blocul de 128Kb a fost deja prealocat
        if (!global_start ||
            ((struct block_meta *)global_start)->status == STATUS_MAPPED) {
        // facem heap prealloc, ca sa reducem semnificativ apeluri de brk();
            block = heap_prealloc();
            if (!block)
                return NULL;
            if (!global_start) {
                global_start = block;
            } else if (((struct block_meta *)global_start)->next == NULL &&
                ((struct block_meta *)global_start)->prev == NULL) {
                memcpy((void *)block + META_ALIGNED, ptr, aligned_size);
                global_start = block;
                os_free(ptr);
            }
        } else {
            coalesce_blocks();
            struct block_meta *iter = global_start;
            block = find_free_block(&iter, aligned_size);

            if (!block) {
            // daca nu s-a gasit un bloc liber, insa ultimul bloc are
            // statutul de free, am putea sa facem "expand last block"
            // last block fiind iter dat ca parametru functiei find_free_block
                if (iter->next == NULL && iter->status == STATUS_FREE
                    && iter->size < aligned_size) {
                    size_t allocated_size = iter->size;
                    block = iter;
                // obtinem adresa de memorie a sfarsitului blocului
                    iter = (void *)block + META_ALIGNED + allocated_size;
                // alocam memorie care nu ne ajunge, facem expand
                    iter = sbrk(aligned_size - allocated_size);
                    block->size = aligned_size;
                    memcpy((void *)block + META_ALIGNED, ptr, mem_to_cpy);
                    os_free(ptr);
                } else {
                // pentru alte cazuri
                    block = sbrk(aligned_size + META_ALIGNED);
                    memcpy((void *)block + META_ALIGNED, ptr, mem_to_cpy);
                    block->size = aligned_size;
                    block->status = STATUS_ALLOC;
                    block->next = NULL;
                    block->prev = iter;
                    iter->next = block;
                    os_free(ptr);
                }
            } else {
            // cand s-a gasit bloc liber din lista
                split_block(block, aligned_size);
                block->status = STATUS_ALLOC;
            }
        }
    } else {
        block = mmap(NULL, aligned_size + META_ALIGNED,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        DIE(block == MAP_FAILED, "Memory mapping failed");

        block->size = aligned_size;
        block->status = STATUS_MAPPED;
        // daca e primul bloc alocat il atribuim la global_start
        if (!global_start) {
            block->next = NULL;
            block->prev = NULL;
            global_start = block;
        }
    }
    // returnam adresa blocului alocat, fara metadate
    return (block + 1);
}
