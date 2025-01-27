import time
from threading import Lock


class Cache:
    def __init__(self):
        self.store = {}
        self.lock = Lock()

    def set(self, user, key, value, ttl=None, on_expire=None):
        expiry = time.time() + ttl if ttl else None
        with self.lock:
            if user not in self.store:
                self.store[user] = {}
            self.store[user][key] = {'value': value, 'expiry': expiry, 'on_expire': on_expire}

    def get(self, user, key):
        with self.lock:
            user_store = self.store.get(user)
            if not user_store:
                return None

            item = user_store.get(key)
            if not item:
                return None

            if item['expiry'] and item['expiry'] < time.time():
                # Key has expired
                self._handle_expiry(key, user, item)
                return None

            return item['value']

    def delete(self, key, user):
        with self.lock:
            user_store = self.store.get(user)
            if user_store and key in user_store:
                del user_store[key]

    def clear(self):
        with self.lock:
            self.store.clear()

    def cleanup(self):
        with self.lock:
            current_time = time.time()
            for user, user_store in list(self.store.items()):
                keys_to_delete = [key for key, item in user_store.items() if item['expiry'] and item['expiry'] < current_time]
                for key in keys_to_delete:
                    self._handle_expiry(key, user, user_store[key])

    def _handle_expiry(self, key, user, item):
        if 'on_expire' in item and callable(item['on_expire']):
            try:
                item['on_expire'](key, item['value'])
            except Exception as e:
                print(f"Error in on_expire callback for key {key}: {e}")
        del self.store[user][key]
        if not self.store[user]:
            del self.store[user]
