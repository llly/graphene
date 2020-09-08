# Bash with Secret Provisioning Examples

This directory contains the Makefile, the template client manifests, and the minimal server and
clients written against the Secret Provisioning library.  This was tested on a machine with SGX v1
and Ubuntu 18.04.

This example uses the Secret Provisioning libraries `secret_prov_attest.so` for clients and
`secret_prov_verify_epid.so`/`secret_prov_verify_dcap.so` for server. These libraries can be found
under `Pal/src/host/Linux-SGX/tools/ra-tls`. Additionally, mbedTLS libraries are required. For
ECDSA/DCAP attestation, the DCAP software infrastructure must be installed and working correctly on
the host.

The current examples work with both EPID (IAS) and ECDSA (DCAP) remote attestation schemes. For
more documentation, refer to `Pal/src/host/Linux-SGX/tools/README.rst`.


## Secret Provisioning server

Reuse server of [ra-tls-secret-prov](../ra-tls-secret-prov), check [README.md](../ra-tls-secret-prov/README.md).

## Bash as Secret Provisioning clients

`bash` and other system executables are unmodified.

It relies on constructor-time secret provisioning and gets the first (and only)
   secret from the environment variable `SECRET_PROVISION_SECRET_STRING`.

As part of secret provisioning flow, all clients create a self-signed RA-TLS certificate with the
embedded SGX quote, send it to the server for verification, and expect secrets in return.

All executables rely on the `LD_PRELOAD` trick that preloads
`libsecret_prov_attest.so` and runs it before the clients' main logic.


# Quick Start

Please make sure that the corresponding RA-TLS libraries (EPID or DCAP versions) are built.

```sh
make -C ../../Pal/src/host/Linux-SGX/tools dcap
```

- start server
```sh
pushd ../ra-tls-secret-prov

make app dcap files/input.txt

RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 ./secret_prov_server_dcap &

popd
```

- test bash and ls as client
```sh

SGX=1 ./pal_loader bash.manifest.sgx -c "ls \$SECRET_PROVISION_SECRET_STRING"
#expected result:
#ls: cannot access 'ffeeddccbbaa99887766554433221100': No such file or directory

kill %%
```
