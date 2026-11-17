# In this module, we propose the simple solution of pre-allocating data ranges before instruction generation starts.
# `Store locations` are 8-byte aligned, 8-byte size locations in memory.

from params.runparams import DO_ASSERT
from initialstate.MemView import MemoryView

import numpy as np
import random

ALIGNMENT_BITS_MAX = 3 # We support alignments 0, 1, 2 and 3 bits (i.e., we don't support quad RISC-V extensions)

class MemStoreState:
    # @param memview must be a fresh MemoryView. Is modified in place by allocating the store locations.
    def __init__(self):
        # Generate the store locations at random and allocate them
        self.store_locations = []

    def init_store_locations(self, num_store_locations: int, memview: MemoryView):
        """
        Find store locations, and allocate them in memview
        """
        for store_location_id in range(num_store_locations):
            # Find a addr in virtual mem, min space = 8
            next_store_location = memview.gen_random_free_addr(ALIGNMENT_BITS_MAX, 1 << ALIGNMENT_BITS_MAX, 0, memview.memsize)
            if next_store_location is None:
                raise ValueError(f"Could not find a next store location. You may want to increase the memory size (for the moment: {memview.memsize:,} B)")
            memview.alloc_mem_range(next_store_location, next_store_location + (1 << ALIGNMENT_BITS_MAX))
            self.store_locations.append(next_store_location)
            if DO_ASSERT:
                assert next_store_location >= 0
                assert next_store_location + (1 << ALIGNMENT_BITS_MAX) <= memview.memsize, f"incorrect next_store_location"
                assert next_store_location % (1 << ALIGNMENT_BITS_MAX) == 0
        self.location_weights = np.ones(num_store_locations)
        # Remember the last store operation address
        self.last_store_addr = self.store_locations[0]

    def pick_store_location(self, alignment_bits: int):
        """
        Modifies the weights in place.

        Args:
            alignment_bits is equal to the requested size. This means we do not support misaligned mem reqs.

        Return:
            The picked location, in addition to updating the state.
        """
        if DO_ASSERT:
            assert alignment_bits >= 0
            assert alignment_bits <= ALIGNMENT_BITS_MAX

        # We first pick a store location. If the alignment is smaller than this size, then we choose uniformly inside the selected store location.
        picked_location_id = random.choices(range(len(self.store_locations)), self.location_weights)[0]
        picked_location = self.store_locations[picked_location_id]
        self.location_weights /= np.sum(self.location_weights)
        self.location_weights[picked_location_id] = 1

        if alignment_bits == ALIGNMENT_BITS_MAX:
            return picked_location
        else:
            # Choose uniformly a sub-location
            factor = 1 << (ALIGNMENT_BITS_MAX - alignment_bits)
            offset_in_location = random.randrange(factor) * (1 << alignment_bits)
            return picked_location + offset_in_location
