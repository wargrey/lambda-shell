#!/bin/sh

RSA_Stone_root=$(dirname `pwd`/$0)
RSA_Prefix=${RSA_Stone_root}/openssl_rsa

RSA_PEM=${RSA_Prefix}.pem
RSA_HEX=${RSA_Prefix}.hex
RSA_PUB=${RSA_Prefix}.pub
RSA_SHA1_Sign=${RSA_Prefix}_sha1.sign

# generate PKCS#1 rsa private key
openssl genrsa -out ${RSA_PEM} 2048
chmod o-rwx ${RSA_PEM}
chmod g-rwx ${RSA_PEM}

# check the private key and output its content for human
openssl rsa -in ${RSA_PEM} -noout -check -text | tee ${RSA_HEX}

# NOTE: the public key format is not the one used by OpenSSH
openssl rsa -in ${RSA_PEM} -pubout > ${RSA_PUB}

# sign with SHA1 and EMSA-v1.5 padding schema using the public key as content
openssl dgst -sha1 -sign ${RSA_PEM} -out ${RSA_SHA1_Sign} ${RSA_PUB}

# verify
openssl dgst -sha1 -verify ${RSA_PUB} -signature ${RSA_SHA1_Sign} ${RSA_PUB}

# done

