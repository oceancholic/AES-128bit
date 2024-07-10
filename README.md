# AES-128bit

# ***********************************************************
# AES 128bit implementation in traditional style (from scratch)
# includes Sbox - InvSbox - Rcon implementations as well
# more info
# https://csrc.nist.gov/pubs/fips/197/final
#
# for educational only and gives insight of how AES works.
# Performance/Efficiency was not a concern
# Tested with NIST Known Answer Test (KAT)
# ************************************************************
#
#       NOT FOR PRODUCTION !!NOT SAFE!! 
# 
# ************************************************************
# only use cryptographic libraries which supports 
# specialized CPU instructions more info at
# https://www.intel.com/content/www/us/en/developer/articles/tool/intel-advanced-encryption-standard-aes-instructions-set.html
#
# Do not use Apples aes.c imlementation they obviously choose performance over security
# Prone to Side Channel attacks. (just saying)
# 
# Contributions and Suggestions are Welcome 
# -------------------------------------------
