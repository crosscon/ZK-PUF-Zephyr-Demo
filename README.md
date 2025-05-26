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

Below is the full proof:

$$
g^v \cdot h^w = g^{r+\alpha R1} \cdot h^{r+\alpha R1} = g^r \cdot g^{\alpha R1} \cdot h^u \cdot h^{\alpha R2} = P \cdot (g^{R_1} \cdot h^{R_2})^{\alpha} = P \cdot \textit{COM}^{\alpha}
$$

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

|                         | ret1                        | ret2                         | ret3                         | ret4                         | ret5             | ret6              | ret7              | ret8              | ret9             | ret10             | ret11             | ret12             |
|-------------------------|-----------------------------|------------------------------|------------------------------|------------------------------|------------------|-------------------|-------------------|-------------------|------------------|-------------------|-------------------|-------------------|
| `PUF_TA_init`           | $g$ (bytes 0-16)            | $g$ (bytes 16-32)            | $g$ (bytes 32-48)            | $g$ (bytes 48-64)            | $h$ (bytes 0-16) | $h$ (bytes 16-32) | $h$ (bytes 32-48) | $h$ (bytes 48-64) | NULL             | NULL              | NULL              | NULL              |
| `PUF_TA_get_commitment` | $\textit{COM}$ (bytes 0-16) | $\textit{COM}$ (bytes 16-32) | $\textit{COM}$ (bytes 32-48) | $\textit{COM}$ (bytes 48-64) | NULL             | NULL              | NULL              | NULL              | NULL             | NULL              | NULL              | NULL              |
| `PUF_TA_get_ZK_proofs`  | $P$ (bytes 0-16)            | $P$ (bytes 16-32)            | $P$ (bytes 32-48)            | $P$ (bytes 48-64)            | $v$ (bytes 0-16) | $v$ (bytes 16-32) | $v$ (bytes 32-48) | $v$ (bytes 48-64) | $w$ (bytes 0-16) | $w$ (bytes 16-32) | $w$ (bytes 32-48) | $w$ (bytes 48-64) |
