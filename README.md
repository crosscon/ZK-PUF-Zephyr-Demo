# Zero-Knowledge PUF CROSSCON HV Demo

App can be used standalone via `lpcxpresso55s69/lpc55s69/cpu0` target but is
aimed to be used within
[crosscon/UC1.1-Manifest](https://github.com/crosscon/UC1.1-Manifest#)

# Available functions

## `PUF_TA_init`

Has to be called before other functions. Initializes PUF hardware and neccessary
ECC variables as well as returns $g$ and $h$.

## `PUF_TA_get_commitment`

Internally produces responses $R_1$ and $R_2$ in response to challenges $C_1$ and
$C_2$ using the device's [PUF](https://en.wikipedia.org/wiki/Physical_unclonable_function).
Commits $R_1$ and $R_2$ using Pedersen commitment into $\textit{COM}$ and returns it.

$\textit{COM}$ can be stored in a public database as it doesn't disclose any information
on $R_1$ / $R_2$ or device's PUF response.

Multiple $\textit{COM}$ can be created using different pairs of $C_1$ / $C_2$.

It's crucial that $C_1 \neq C_2$.

## `PUF_TA_get_ZK_proofs`

Once the device is enrolled, it can use this function to authenticate itself to other
devices. The process is initiated by the verifier, which sends
challenges $C_1$ and $C_2$ , along with a nonce $n$. The nonce ensures the
freshness of the authentication process and prevents the replay of old or recorded
protocol runs.

Two random values $r$ and $u$ are created which then formulate a commitment
$P=g^r \cdot h^u$.

This is used to create a hash $\alpha = \textit{SHA256}(P, n)$.

Two zero-knowledge proofs are calculated, denoted as $v$ and $w$, where
$v = r + \alpha R_1$ and $w = u + \alpha R_1$ . These proofs enable to demonstrate
knowledge of $R_1$ and $R_2$ to the verifier, without disclosing the actual values of
$R_1$ and $R_2$.

$P$, $v$ and $w$ are returned by the function.

These along with saved $\textit{COM}$, $g$, $h$ and $n$ can be used to authenticate device.
Example scripts for this purpose are available in [scripts/proofs](./scripts/proofs).

For more info on how to proof/authenticate take a look at [scripts/proofs/README.md](./scripts/proofs/README.md)

## API

The app uses [shared memory regions](./application/src/crosscon_hv/crosscon_hv_config.h)
and interrupts to communicate with other "VMs" running on
[CROSSCON Hypervisor](https://github.com/crosscon/CROSSCON-Hypervisor/tree/main).

An example of client-side communication can be seen at [GUEST_VM0](https://github.com/crosscon/ZK-PUF-Zephyr-Demo/tree/GUEST_VM0)
branch.

### Function calls

|                         | uuid                                 | arg1            | arg2            | arg3            | arg4 | arg5 | arg6 | arg7 | arg8 | arg9 | arg10 | arg11 | arg12 |
|-------------------------|--------------------------------------|-----------------|-----------------|-----------------|------|------|------|------|------|------|-------|-------|-------|
| `PUF_TA_init`           | `0x00112233445566778899AABBCCDDEEFF` | NULL            | NULL            | NULL            | NULL | NULL | NULL | NULL | NULL | NULL | NULL  | NULL  | NULL  |
| `PUF_TA_get_commitment` | `0x112233445566778899AABBCCDDEEFF00` | $C_1$ (16-byte) | $C_1$ (16-byte) | NULL            | NULL | NULL | NULL | NULL | NULL | NULL | NULL  | NULL  | NULL  |
| `PUF_TA_get_ZK_proofs`  | `0x2233445566778899AABBCCDDEEFF0011` | $C_2$ (16-byte) | $C_2$ (16-byte) | Nonce (16-byte) | NULL | NULL | NULL | NULL | NULL | NULL | NULL  | NULL  | NULL  |

### Function returns

|                         | ret1                          | ret2                           | ret3                          | ret4                           | ret5               | ret6                | ret7               | ret8                | ret9             | ret10             | ret11             | ret12             |
|-------------------------|-------------------------------|--------------------------------|-------------------------------|--------------------------------|--------------------|---------------------|--------------------|---------------------|------------------|-------------------|-------------------|-------------------|
| `PUF_TA_init`           | $g_x$ (bytes 0-16)            | $g_x$ (bytes 16-32)            | $g_y$ (bytes 0-16)            | $g_y$ (bytes 16-32)            | $h_x$ (bytes 0-16) | $h_x$ (bytes 16-32) | $h_y$ (bytes 0-16) | $h_y$ (bytes 16-32) | NULL             | NULL              | NULL              | NULL              |
| `PUF_TA_get_commitment` | $\textit{COM}_x$ (bytes 0-16) | $\textit{COM}_x$ (bytes 16-32) | $\textit{COM}_y$ (bytes 0-16) | $\textit{COM}_y$ (bytes 16-32) | NULL               | NULL                | NULL               | NULL                | NULL             | NULL              | NULL              | NULL              |
| `PUF_TA_get_ZK_proofs`  | $P_x$ (bytes 0-16)            | $P_x$ (bytes 16-32)            | $P_y$ (bytes 0-16)            | $P_y$ (bytes 16-32)            | $v$ (bytes 0-16)   | $v$ (bytes 16-32)   | $v$ (bytes 32-48)  | $v$ (bytes 48-64)   | $w$ (bytes 0-16) | $w$ (bytes 16-32) | $w$ (bytes 32-48) | $w$ (bytes 48-64) |

## Additional Information

$\textit{COM}$, $g$, $h$ and $P$ are of type ECP point but to be transferrable over a 16-byte aligned channels the first byte from [Mbed TLS's `mbectls_ecp_point`](https://mbed-tls.readthedocs.io/projects/api/en/development/api/struct/structmbedtls__ecp__point/) was stripped. To reconstruct the MbedTLS compatible byte sequence a byte with value `0x04` needs to be prepended. The final structure thus should look like `0x04||X||Y`.
