"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/transport_config.py
"""

# Option defaults

_DEFAULT_LHOST = "127.0.0.1"
_DEFAULT_LPORT = 4444
_DEFAULT_RETRY_COUNT = 10
_DEFAULT_RETRY_WAIT = 5


class TransportConfig:
    """
    Mixin that normalises transport-layer options for Windows stager mixins.
    Mirrors Msf::Payload::TransportConfig (transport_config.rb).
    """

    # Internal helpers

    def _tc_get(self, ctx, name, default=None):
        """
        Safely retrieve an option value from the context.

        Returns *default* when the context has no get_option method,
        when the key is absent, or when the returned value is None / "".
        """
        try:
            getter = getattr(ctx, "get_option", None)
            if not callable(getter):
                return default
            val = getter(name)
            return val if val not in (None, "") else default

        except Exception:  # pylint: disable=broad-exception-caught
            return default

    def _tc_get_int(self, ctx, name, default):
        """Return an option as int, falling back to *default* on error."""
        val = self._tc_get(ctx, name, default)
        try:
            if val is not None and isinstance(val, (str, int, float)):
                return int(val)
            raise ValueError("Transfort config :: object not INTEGER!")

        except (ValueError, TypeError):
            return default

    def _tc_get_str(self, ctx, name, default):
        """Return an option as stripped str, falling back to *default*."""
        val = self._tc_get(ctx, name, default)
        try:
            return str(val).strip() or default

        except Exception:  # pylint: disable=broad-exception-caught
            return default

    #  Public helpers

    def transport_config_reverse_tcp(self, ctx):
        """
        Return a normalised config dict for reverse-TCP transports.
        """
        lhost = self._tc_get_str(ctx, "LHOST", _DEFAULT_LHOST)
        lport = self._tc_get_int(ctx, "LPORT", _DEFAULT_LPORT)
        retry_count = self._tc_get_int(ctx, "StagerRetryCount", _DEFAULT_RETRY_COUNT)
        retry_wait = self._tc_get_int(ctx, "StagerRetryWait", _DEFAULT_RETRY_WAIT)

        # Clamp to sane bounds
        lport = max(1, min(lport, 65535))
        retry_count = max(1, retry_count)
        retry_wait = max(0, retry_wait)

        return {
            "lhost": lhost,
            "lport": lport,
            "retry_count": retry_count,
            "retry_wait": retry_wait,
        }

    def transport_config_bind_tcp(self, ctx):
        """
        Return a normalised config dict for bind-TCP transports.
        """
        lport = self._tc_get_int(ctx, "LPORT", _DEFAULT_LPORT)
        lport = max(1, min(lport, 65535))

        return {
            "lport": lport,
        }
