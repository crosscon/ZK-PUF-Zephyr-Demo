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

The app uses a subset of Global Platform Client API for communication.

An example of client-side communication can be seen at [GUEST_VM0](https://github.com/crosscon/ZK-PUF-Zephyr-Demo/tree/GUEST_VM0)
branch.

**TA UUID** - `0x00112233445566778899AABBCCDDEEFF`

| handler                 | Function ID   | Parameter 1 (`atrr`/`b`)                                      | Parameter 2 (`atrr`/`b`)                                      | Parameter 3 (`atrr`/`b`)                                            | Parameter 4 (`atrr`/`b`)                                          |
|-------------------------|---------------|---------------------------------------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------|-------------------------------------------------------------------|
| `PUF_TA_init`           | `0x00112233`  | $g_x$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 32 bytes)        | $g_y$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 32 bytes)        | $h_x$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 32 bytes)              | $h_y$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 32 bytes)            |
| `PUF_TA_get_commitment` | `0x11223344`  | $C_1$ (`TEE_PARAM_ATTR_TYPE_MEMREF_INPUT` / 32 bytes)         | $C_2$ (`TEE_PARAM_ATTR_TYPE_MEMREF_INPUT` / 32 bytes)         | $\textit{COM}_x$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 32 bytes)   | $\textit{COM}_y$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 32 bytes) |
| `PUF_TA_get_ZK_proofs`  | `0x22334455`  | $C_1$ / $P_x$ (`TEE_PARAM_ATTR_TYPE_MEMREF_INOUT` / 32 bytes) | $C_2$ / $P_y$ (`TEE_PARAM_ATTR_TYPE_MEMREF_INOUT` / 32 bytes) | $n$ / $v$ (`TEE_PARAM_ATTR_TYPE_MEMREF_INOUT` / 64 bytes)           | $w$ (`TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT` / 64 bytes)              |

## Additional Information

$\textit{COM}$, $g$, $h$ and $P$ are Eliptic Curve Points derived from
[Mbed TLS's `mbectls_ecp_point`](https://mbed-tls.readthedocs.io/projects/api/en/development/api/struct/structmbedtls__ecp__point/).
To reconstruct the MbedTLS compatible byte sequence a byte with value `0x04`
needs to be prepended. The final structure thus should look like `0x04||X||Y`.

## Demo's

### Running

![](./doc/gif/running_demo.gif)

### Proof

![](./doc/gif/proof_demo.gif)

## License

See LICENSE file.

## Acknowledgments

The work presented in this repository is part of the
[CROSSCON project](https://crosscon.eu/) that received funding from the European
Union’s Horizon Europe research and innovation programme under grant agreement
No 101070537.

<p align="center">
    <img src="https://crosscon.eu/sites/crosscon/themes/crosscon/images/eu.svg" width=10% height=10%>
</p>

<p align="center">
    <img src="https://crosscon.eu/sites/crosscon/files/public/styles/large_1080_/public/content-images/media/2023/crosscon_logo.png?itok=LUH3ejzO" width=25% height=25%>
</p>
