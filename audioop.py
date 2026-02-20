# Stub module for Python 3.13+ where stdlib audioop was removed.
# discord.py imports audioop even if you never use voice.

def _nope(*args, **kwargs):
    raise NotImplementedError("audioop is not available. Voice features disabled.")

add = avg = bias = cross = findfactor = findmax = getsample = lin2adpcm = lin2alaw = lin2lin = lin2ulaw = max = minmax = mul = ratecv = reverse = rms = tomono = tostereo = ulaw2lin = alaw2lin = adpcm2lin = _nope
