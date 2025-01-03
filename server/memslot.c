/* -*- Mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
   Copyright (C) 2009,2010 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include <config.h>

#include <inttypes.h>

#include "memslot.h"

static uintptr_t __get_clean_virt(RedMemSlotInfo *info, QXLPHYSICAL addr)
{
    return addr & info->memslot_clean_virt_mask;
}

static void print_memslots(RedMemSlotInfo *info)
{
    int i;
    int x;

    for (i = 0; i < info->num_memslots_groups; ++i) {
        for (x = 0; x < info->num_memslots; ++x) {
            if (!info->mem_slots[i][x].virt_start_addr &&
                !info->mem_slots[i][x].virt_end_addr) {
                continue;
            }
            printf("id %d, group %d, virt start %" PRIxPTR ", virt end %" PRIxPTR ", generation %u,"
                   " delta %" PRIxPTR "\n",
                   x, i, info->mem_slots[i][x].virt_start_addr,
                   info->mem_slots[i][x].virt_end_addr, info->mem_slots[i][x].generation,
                   info->mem_slots[i][x].address_delta);
            }
    }
}

/* return 1 if validation successfull, 0 otherwise */
int memslot_validate_virt(RedMemSlotInfo *info, uintptr_t virt, int slot_id,
                          uint32_t add_size, uint32_t group_id)
{
    MemSlot *slot;

    slot = &info->mem_slots[group_id][slot_id];
    if ((virt + add_size) < virt) {
        spice_critical("virtual address overlap");
        return 0;
    }

    if (virt < slot->virt_start_addr || (virt + add_size) > slot->virt_end_addr) {
        print_memslots(info);
        spice_warning("virtual address out of range"
              "    virt=0x%" G_GINTPTR_MODIFIER "x+0x%x slot_id=%d group_id=%d\n"
              "    slot=0x%" G_GINTPTR_MODIFIER "x-0x%" G_GINTPTR_MODIFIER "x"
              " delta=0x%" G_GINTPTR_MODIFIER "x",
              virt, add_size, slot_id, group_id,
              slot->virt_start_addr, slot->virt_end_addr, slot->address_delta);
        return 0;
    }
    return 1;
}

uintptr_t memslot_max_size_virt(RedMemSlotInfo *info,
                                uintptr_t virt, int slot_id,
                                uint32_t group_id)
{
    MemSlot *slot;

    slot = &info->mem_slots[group_id][slot_id];

    if (virt < slot->virt_start_addr || virt > slot->virt_end_addr) {
        return 0;
    }
    return slot->virt_end_addr - virt;
}

/*
 * returns NULL on failure.
 */
void *memslot_get_virt(RedMemSlotInfo *info, QXLPHYSICAL addr, uint32_t add_size,
                       int group_id)
{
    int slot_id;
    int generation;
    uintptr_t h_virt;

    MemSlot *slot;

    if (group_id >= info->num_memslots_groups) {
        spice_critical("group_id too big");
        return NULL;
    }

    slot_id = memslot_get_id(info, addr);
    if (slot_id >= info->num_memslots) {
        print_memslots(info);
        spice_critical("slot_id %d too big, addr=%" G_GINT64_MODIFIER "x", slot_id, addr);
        return NULL;
    }

    slot = &info->mem_slots[group_id][slot_id];

    generation = memslot_get_generation(info, addr);
    if (generation != slot->generation) {
        print_memslots(info);
        spice_critical("address generation is not valid, group_id %d, slot_id %d, "
                       "gen %d, slot_gen %d",
                       group_id, slot_id,
                       generation, slot->generation);
        return NULL;
    }

    h_virt = __get_clean_virt(info, addr);
    h_virt += slot->address_delta;

    if (!memslot_validate_virt(info, h_virt, slot_id, add_size, group_id)) {
        return NULL;
    }

    return (void *)h_virt;
}

void memslot_info_init(RedMemSlotInfo *info,
                       uint32_t num_groups, uint32_t num_slots,
                       uint8_t generation_bits,
                       uint8_t id_bits,
                       uint8_t internal_groupslot_id)
{
    // Check environment variables to override defaults
    const char* env_groups = getenv("SPICE_MEMSLOT_GROUPS");
    const char* env_slots = getenv("SPICE_MEMSLOT_SLOTS"); 
    const char* env_gen_bits = getenv("SPICE_MEMSLOT_GEN_BITS");
    const char* env_id_bits = getenv("SPICE_MEMSLOT_ID_BITS");

    if (env_groups) {
        num_groups = atoi(env_groups);
    }
    if (env_slots) {
        num_slots = atoi(env_slots);
    }
    if (env_gen_bits) {
        generation_bits = atoi(env_gen_bits);
    }
    if (env_id_bits) {
        id_bits = atoi(env_id_bits);
    }

    // Apply minimum values to prevent invalid configurations
    num_groups = MAX(1, num_groups);
    num_slots = MAX(1, num_slots);
    generation_bits = MAX(1, generation_bits); 
    id_bits = MAX(1, id_bits);

    spice_assert(num_slots > 0);
    spice_assert(num_groups > 0);

    info->num_memslots_groups = num_groups;
    info->num_memslots = num_slots;
    info->generation_bits = generation_bits;
    info->mem_slot_bits = id_bits;
    info->internal_groupslot_id = internal_groupslot_id;

    info->mem_slots = g_new(MemSlot *, num_groups);

    for (i = 0; i < num_groups; ++i) {
        info->mem_slots[i] = g_new0(MemSlot, num_slots);
    }

    /* TODO: use QXLPHYSICAL_BITS */
    info->memslot_id_shift = 64 - info->mem_slot_bits;
    info->memslot_gen_shift = 64 - (info->mem_slot_bits + info->generation_bits);
    info->memslot_gen_mask = ~((QXLPHYSICAL)-1 << info->generation_bits);
    info->memslot_clean_virt_mask = (((QXLPHYSICAL)(-1)) >>
                                       (info->mem_slot_bits + info->generation_bits));
}

void memslot_info_destroy(RedMemSlotInfo *info)
{
    uint32_t i;

    for (i = 0; i < info->num_memslots_groups; ++i) {
        g_free(info->mem_slots[i]);
    }
    g_free(info->mem_slots);
}

void memslot_info_add_slot(RedMemSlotInfo *info, uint32_t slot_group_id, uint32_t slot_id,
                           uintptr_t addr_delta, uintptr_t virt_start, uintptr_t virt_end,
                           uint32_t generation)
{
    spice_assert(info->num_memslots_groups > slot_group_id);
    spice_assert(info->num_memslots > slot_id);

    info->mem_slots[slot_group_id][slot_id].address_delta = addr_delta;
    info->mem_slots[slot_group_id][slot_id].virt_start_addr = virt_start;
    info->mem_slots[slot_group_id][slot_id].virt_end_addr = virt_end;
    info->mem_slots[slot_group_id][slot_id].generation = generation;
}

void memslot_info_del_slot(RedMemSlotInfo *info, uint32_t slot_group_id, uint32_t slot_id)
{
    spice_return_if_fail(info->num_memslots_groups > slot_group_id);
    spice_return_if_fail(info->num_memslots > slot_id);

    info->mem_slots[slot_group_id][slot_id].virt_start_addr = 0;
    info->mem_slots[slot_group_id][slot_id].virt_end_addr = 0;
}

void memslot_info_reset(RedMemSlotInfo *info)
{
        uint32_t i;
        for (i = 0; i < info->num_memslots_groups; ++i) {
            memset(info->mem_slots[i], 0, sizeof(MemSlot) * info->num_memslots);
        }
}
