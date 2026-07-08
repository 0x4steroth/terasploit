"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/modules/module_storage.py
"""

import time


class ModuleEntry:
    """
    Thin wrapper that associates an instantiated module with its metadata.
    """

    def __init__(self, name, module):
        self.name = name
        self.module = module
        self.loaded_at = time.time()

    def cleanup(self):
        """
        Invoke the module's stop() hook if one exists.

        The hook is optional.  Modules that hold no persistent resources
        may omit it entirely without causing any error here.
        """
        if hasattr(self.module, "stop") and callable(self.module.stop):
            self.module.stop()

    def __repr__(self):
        return f"ModuleEntry({self.name!r})"


class ModuleStorage:
    """
    Session registry for the active exploit/auxiliary module, payload,
    and encoder.
    """

    def __init__(self):
        self._module = None
        self._payload = None
        self._encoder = None

    # Setters
    def set_module(self, name, module):
        """
        Register a new exploit or auxiliary module.

        Cleans up the previous module first if one was loaded.
        Returns the newly created ModuleEntry.
        """
        if self._module is not None:
            self._module.cleanup()
        self._module = ModuleEntry(name, module)
        return self._module

    def set_payload(self, name, module):
        """
        Register a new payload, replacing any previous one.

        Returns the newly created ModuleEntry.
        """
        if self._payload is not None:
            self._payload.cleanup()
        self._payload = ModuleEntry(name, module)
        return self._payload

    def set_encoder(self, name, module):
        """
        Register a new encoder, replacing any previous one.

        Returns the newly created ModuleEntry.
        """
        if self._encoder is not None:
            self._encoder.cleanup()
        self._encoder = ModuleEntry(name, module)
        return self._encoder

    # Getters
    def module(self):
        """
        Return the active ModuleEntry for the exploit/auxiliary slot, or None.
        """
        return self._module

    def payload(self):
        """
        Return the active ModuleEntry for the payload slot, or None.
        """
        return self._payload

    def encoder(self):
        """
        Return the active ModuleEntry for the encoder slot, or None.
        """
        return self._encoder

    def has_module(self):
        """
        Return True if an exploit/auxiliary module is currently loaded.
        """
        return self._module is not None

    def has_payload(self):
        """
        Return True if a payload is currently loaded.
        """
        return self._payload is not None

    def has_encoder(self):
        """
        Return True if an encoder is currently loaded.
        """
        return self._encoder is not None

    # Clearers
    def clear_module(self):
        """
        Unload the active exploit/auxiliary module.

        Returns True if a module was present and cleaned up, False otherwise.
        """
        if self._module is not None:
            self._module.cleanup()
            self._module = None
            return True
        return False

    def clear_payload(self):
        """
        Unload the active payload.

        Returns True if a payload was present and cleaned up.
        """
        if self._payload is not None:
            self._payload.cleanup()
            self._payload = None
            return True
        return False

    def clear_encoder(self):
        """
        Unload the active encoder.

        Returns True if an encoder was present and cleaned up.
        """
        if self._encoder is not None:
            self._encoder.cleanup()
            self._encoder = None
            return True
        return False

    def clear_all(self):
        """
        Unload all active components in reverse dependency order:
        encoder first, then payload, then module.

        Reverse order is used so that components which depend on the
        module (like the payload) are torn down before the module itself.
        """
        self.clear_encoder()
        self.clear_payload()
        self.clear_module()

    def __repr__(self):
        parts = []
        if self._module:
            parts.append(f"module={self._module.name!r}")

        if self._payload:
            parts.append(f"payload={self._payload.name!r}")

        if self._encoder:
            parts.append(f"encoder={self._encoder.name!r}")

        return f"ModuleStorage({', '.join(parts) if parts else 'empty'})"
