# 3.3
  - add new field in the log: cipher_info. Since cipher plugin support multi encryption of field that can be both fully encrypted or partial encrypted, it was impossible to decrypt partial field simply because people don't know where encryption starts and where it ends. For this reason in this version you find cipher info field in your log that tells you the information about all the key that has been crypted and 2 indices (start and end) that will tell you the exact position of the encrypted value. 

# 3.0
  - Support multi encryption adding new parameters "key_regex" and "value_regex" that allow users to specify regex expression to crypt multifields and/or
   values that match the "value_regex"
  - Remove key parameters and now read from file both iv and key.

# 2.1
  - Support for LogStash 5.x and added mutex.
  - Change source and target from string to array.
# 2.0.5
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.4
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.3
 - fixes base64 encoding issue, adds support for random IVs

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
