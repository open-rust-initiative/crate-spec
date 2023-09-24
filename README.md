# crate-spec
`crate-spec` is a new file format we've designed for Rust, characterized by its safety, reliability, and robustness. This brand-new file format allows Crate files to be mirrored and cached anywhere while providing end-to-end data integrity assurance and authentication capabilities.

We provide an application(crate-spec) to generate (encode) and decode new crate file.
## Encode
When using the encode (`-e`) option, the program will invoke the `cargo package` command to check and package the Rust project and perform additional operations such as signing it, ultimately generating a `.scrate` file.

You may use the following options.
* -e (**must provide**)

This tells the application to encode Rust project to `.scrate` file.
* -r (**must provide**)

This provides the path to the root certificate authority (CA) files (`.pem`).
* -c (**must provide**)

This provides the publisher's certificate (`.pem`).
* -p (**must provide**)

This provides the publisher's private key for signing the file (`.pem`).
* -o (**must provide**)

This specifies the directory path for dumping the `.scrate` file.

* \<project path\> (**must provide**)

This is provided at the end of the command to specify the Rust project for encoding.

Here's an encoding example, which you can also find in `test/example/encode_crate.sh`

```bash
crate-spec -e  \
           -r test/root-ca.pem \
           -c test/cert.pem \
           -p test/key.pem \ 
           -o test/output  \
           ../crate-spec
```


## Decode

When using the decode (`-d`) option for decoding, the program will decode the .scrate file, verifying its integrity and source. Once the verification passes, it will decode the file back into the original `.crate` file, which is used by Cargo, and also dump the package's metadata to `{crate_name}-{version}-metadata.txt`.

You may use the following options.

* -d (**must provide**)

This tells the application to decode `.scrate` file.

* -r (**must provide**)

This provides the path to the root certificate authority (CA) files (`.pem`).

* -o (**must provide**)

This specifies the directory path for decode the `.scrate` file.

* \<`.scrate` file path\> (**must provide**)

This is provided at the end of the command to specify the Rust `.scrate` file for decoding.

Here's a decoding example, which you can also find in `test/example/decode_crate.sh`

```bash
crate-spec -d  \
           -r test/root-ca.pem \
           -o test/output  \
           test/output/crate-spec-0.1.0.scrate
```

## Examples
You can find the example in `test/example`.

### 1. encode Rust project
```bash
sh encode_crate.sh
```

This will encode this project (`crate-spec`) to `crate-spec-0.1.0.scrate` file in `test/output`.

----------------
### 2. decode `.scrate` file
```bash
sh decode_crate.sh
```

This will decode the `.scrate` file to original crate file `crate-spec-0.1.0.crate` and dump the metadata file `crate-spec-0.1.0-metadata.txt` in `test/output`.

-------

### 3. check integrity

- **The situations of file transfer errors**

**a.** First you generate the `.scarte` file.
```bash
sh encode_crate.sh
```

**b.** Assuming that during the scrate file transfer process, some bytes have encountered errors.
```bash
sh hack_file.sh 0
```
This will change some bytes in `crate-spec-0.1.0.scrate` file.

**c.** Following this step, when you execute decode_crate.sh, you will encounter the subsequent error message:

```bash
>> sh decode_crate.sh
fingerprint not right
```

- **The situation of intentionally tampering with files**

**a.** First you generate the `.scarte` file again.
```bash
sh encode_crate.sh
```

**b.** Assuming someone has modified the file and recalculated the fingerprint.
```bash
sh hack_file.sh 1
```
This will change some bytes in `crate-spec-0.1.0.scrate` file and recalculate the fingerprint.

**c.** Following this step, when you execute decode_crate.sh, you will encounter the subsequent error message:

```bash
>> sh decode_crate.sh
file sig not right
```