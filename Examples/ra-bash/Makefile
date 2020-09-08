# Use one of these commands to build the manifest for Bash:
#
# - make
# - make DEBUG=1
# - make SGX=1
# - make SGX=1 DEBUG=1
#
# Use `make clean` to remove Graphene-generated files.

# Listing the programs to be run inside the bash script
PROGRAMS = ls cat rm cp date

# Relative path to Graphene root and key for enclave signing
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: bash.manifest $(addsuffix .manifest,$(PROGRAMS)) pal_loader
ifeq ($(SGX),1)
all: bash.token $(addsuffix .token,$(PROGRAMS)) dcap
endif

.PHONY: dcap
dcap: secret_prov_server_dcap libsecret_prov_attest.so libsecret_prov_verify_dcap.so

include ../../Scripts/Makefile.configs


############################# MBEDTLS DEPENDENCY ##############################

MBEDTLS_VERSION ?= 2.21.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 320e930b7596ade650ae4fc9ba94b510d05e3a7d63520e121d8fdc7a21602db9

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= https://github.com/ARMmbed/mbed-crypto/archive/
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	$(GRAPHENEDIR)/Scripts/download --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) \
		--sha256 $(MBEDTLS_CHECKSUM)

$(MBEDCRYPTO_SRC):
	$(GRAPHENEDIR)/Scripts/download --output $@ --url $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) \
		--sha256 $(MBEDCRYPTO_CHECKSUM)

mbedtls/CMakeLists.txt: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
	tar --touch -xzf $(MBEDTLS_SRC)
	tar --touch -xzf $(MBEDCRYPTO_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	$(RM) -r mbedtls/crypto
	mv mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls
	mv mbedtls/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls/crypto
	mkdir mbedtls/install
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C && make SHARED=1 DESTDIR=install install .

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += -Wall -std=c11 -I$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls
LFLAGS += -Wl,-rpath,. -L. -lmbedcrypto -lmbedtls -lmbedx509

secret_prov_server_epid: src/secret_prov_server.c libsecret_prov_verify_epid.so \
			 libmbedcrypto.so libmbedtls.so libmbedx509.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -lsecret_prov_verify_epid -pthread -o $@

# linker option --no-as-needed is required because SGX DCAP library (libsgx_dcap_quoteverify.so)
# does dlopen() instead of directly linking against libsgx_urts.so, and without this option
# compilers remove the "seemingly unused" libsgx_urts.so
secret_prov_server_dcap: src/secret_prov_server.c libsecret_prov_verify_dcap.so \
			 libmbedcrypto.so libmbedtls.so libmbedx509.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -Wl,--no-as-needed -lsgx_urts -lsecret_prov_verify_dcap -pthread -o $@

secret_prov_client: src/secret_prov_client.c libsecret_prov_attest.so \
		    libmbedcrypto.so libmbedtls.so libmbedx509.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -lsecret_prov_attest -o $@

secret_prov_min_client: src/secret_prov_min_client.c libmbedcrypto.so libmbedtls.so libmbedx509.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

secret_prov_pf_client: src/secret_prov_pf_client.c libmbedcrypto.so libmbedtls.so libmbedx509.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

########################### COPIES FOR CONVENIENCE ############################

pf_crypt: libsgx_util.so
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/pf_crypt/$@ $@

libmbedcrypto.so: mbedtls/CMakeLists.txt
	cp mbedtls/install/lib/$@.* .
	ln -s $@.* $@

libmbedtls.so: mbedtls/CMakeLists.txt
	cp mbedtls/install/lib/$@.* .
	ln -s $@.* $@

libmbedx509.so: mbedtls/CMakeLists.txt
	cp mbedtls/install/lib/$@.* .
	ln -s $@.* $@

libsgx_util.so:
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/common/$@ .

libsecret_prov_attest.so:
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/$@ .

libsecret_prov_verify_dcap.so: libmbedcrypto.so libmbedx509.so libmbedtls.so libsgx_util.so
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/$@ .



# Program dependencies (generate from ldd):
#
# For SGX, the manifest needs to list all the libraries loaded during the
# execution, so that the signer can include the file checksums.
#
# The dependencies are generated from the ldd results.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc
# binaries are already listed in the manifest template, so we can skip them
# from the ldd results. This list also contains some runtime deps of Bash.
GLIBC_DEPS = linux-vdso /lib64/ld-linux-x86-64 libc libm librt libdl libutil libpthread \
             libselinux libpcre libacl libattr

# Listing all Bash dependencies, besides Glibc libraries
.INTERMEDIATE: $(addsuffix .deps,bash $(PROGRAMS))
%.deps:
	ldd $(shell which $(basename $@)) | \
		awk '{if ($$2 =="=>") {split($$1,s,/\./); print s[1]}}' | \
		sort | uniq | (grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) || true) > $@

# Generating manifest rules for Bash dependencies
.INTERMEDIATE: $(addsuffix .trusted-libs,bash $(PROGRAMS))
%.trusted-libs: %.deps
	for F in `cat $<`; do \
		P=`ldd $(shell which $(basename $@)) | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = file:$$P\\\\n"; \
	done > $@

.INTERMEDIATE: trusted-children
trusted-children:
	@for F in $(PROGRAMS); do \
		echo -n "sgx.trusted_children.$$F = file:$$F.sig\\\\n"; \
		echo -n "sgx.trusted_files.$$F    = file:`which $$F`\\\\n"; \
		done > $@

bash.manifest: manifest.template trusted-children bash.trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARGV0_OVERRIDE)|bash|g' \
		-e 's|$$(EXECPATH)|'"$(shell which bash)"'|g' \
		-e 's|$$(EXECDIR)|'"$(shell dirname $(shell which bash))"'|g' \
		-e 's|$$(TRUSTED_LIBS)|'"`cat bash.trusted-libs`"'|g' \
		-e 's|$$(TRUSTED_CHILDREN)|'"`cat trusted-children`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

$(addsuffix .manifest,$(PROGRAMS)): %.manifest: manifest.template %.trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARGV0_OVERRIDE)|'"$(basename $@)"'|g' \
		-e 's|$$(EXECPATH)|'"$(shell which $(basename $@))"'|g' \
		-e 's|$$(EXECDIR)|'"$(shell dirname $(shell which $(basename $@)))"'|g' \
		-e 's|$$(TRUSTED_LIBS)|'"`cat $(basename $@).trusted-libs`"'|g' \
		-e 's|$$(TRUSTED_CHILDREN)||g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Generating the SGX-specific manifest (*.manifest.sgx), the enclave signature,
# and the token for enclave initialization.
bash.manifest.sgx: bash.manifest $(addsuffix .manifest.sgx,$(PROGRAMS)) dcap
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

bash.sig: bash.manifest.sgx

bash.token: bash.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output bash.token -sig bash.sig

$(addsuffix .manifest.sgx,$(PROGRAMS)): %.manifest.sgx: %.manifest dcap
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

$(addsuffix .sig,$(PROGRAMS)): %.sig: %.manifest.sgx

$(addsuffix .token,$(PROGRAMS)): %.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $(basename $<).token -sig $(basename $<).sig

# Extra executables
pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: regression
regression: all
	@mkdir -p scripts/testdir

	./pal_loader bash.manifest -c "ls" > OUTPUT
	@grep -q "Makefile" OUTPUT && echo "[ Success 1/6 ]"
	@rm OUTPUT

	./pal_loader bash.manifest -c "cd scripts && bash bash_test.sh 1" > OUTPUT
	@grep -q "hello 1" OUTPUT      && echo "[ Success 2/6 ]"
	@grep -q "createdfile" OUTPUT  && echo "[ Success 3/6 ]"
	@grep -q "somefile" OUTPUT     && echo "[ Success 4/6 ]"
	@grep -q "current date" OUTPUT && echo "[ Success 5/6 ]"
	@rm OUTPUT

	./pal_loader bash.manifest -c "cd scripts && bash bash_test.sh 3" > OUTPUT
	@grep -q "hello 3" OUTPUT      && echo "[ Success 6/6 ]"
	@rm OUTPUT

	@rm -rf scripts/testdir


.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT scripts/testdir/*

.PHONY: distclean
distclean: clean
