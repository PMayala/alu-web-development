#!/usr/bin/env python3
"""First-In First-Out caching module.
"""
from collections import OrderedDict
from base_caching import BaseCaching


class FIFOCache(BaseCaching):
    """
    FIFO Cache: discards the first item inserted when the limit is reached.
    """

    def __init__(self):
        """Initialize the cache."""
        super().__init__()
        self.cache_data = OrderedDict()

    def put(self, key, item):
        """Add an item in the cache using FIFO strategy."""
        if key is None or item is None:
            return

        # Avoid updating order if key already exists
        if key not in self.cache_data:
            self.cache_data[key] = item
        else:
            # Just update the value without affecting order
            self.cache_data[key] = item
            return

        if len(self.cache_data) > BaseCaching.MAX_ITEMS:
            discarded_key, _ = self.cache_data.popitem(last=False)
            print("DISCARD:", discarded_key)

    def get(self, key):
        """Retrieve an item by key."""
        return self.cache_data.get(key, None)

