from . import aes_gcm
from . import aes_ccm
from . import aes_siv
from . import aes_gcmsiv
from . import chacha20_poly1305
from . import aes_0cb3

# Map algorithm names to the corresponding module
ALGORITHMS = {
    "aes_gcm": aes_gcm,
    "aes_ccm": aes_ccm,
    "aes_siv": aes_siv,
    "aes_gcmsiv": aes_gcmsiv,
    "chacha20_poly1305": chacha20_poly1305,
    "aes_0cb3": aes_0cb3,
}
