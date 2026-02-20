"""
Minimal stub for Python 3.13+ where the stdlib 'audioop' module was removed.

discord.py imports 'audioop' even if you never use voice.
This stub exists only to satisfy the import so non-voice bots can run.

If you use voice features later, replace this with a real implementation
or run on Python 3.12/3.11.
"""

def _nope(*args, **kwargs):
    raise NotImplementedError(
        "audioop is not available in this Python version. "
        "Voice/audio processing is not supported with this stub."
    )

# Common audioop API surface (discord.py imports the module; voice uses these)
add = _nope
avg = _nope
bias = _nope
cross = _nope
findfactor = _nope
findmax = _nope
getsample = _nope
lin2adpcm = _nope
lin2alaw = _nope
lin2lin = _nope
lin2ulaw = _nope
max = _nope
minmax = _nope
mul = _nope
ratecv = _nope
reverse = _nope
rms = _nope
tomono = _nope
tostereo = _nope
ulaw2lin = _nope
alaw2lin = _nope
adpcm2lin = _nope
